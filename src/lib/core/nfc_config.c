/* ngfw - strict JSON (RFC 8259) configuration tree (L1 core).
 *
 * Accepts: the full RFC 8259 value grammar with UTF-8 string content.
 * Rejects: trailing garbage, leading zeros, control characters in strings,
 * lone surrogates, embedded NUL escapes, and nesting beyond CFG_MAX_DEPTH.
 * Input must be valid UTF-8; bytes are stored verbatim.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <ngfw/config.h>
#include <ngfw/platform.h>

#define CFG_MAX_DEPTH 64
#define CFG_MAX_NUMBER_CHARS 64

struct nfc_cfg
{
  enum nfc_cfg_type type;
  union
  {
    int boolean;
    int64_t integer;
    double real;
    char *text;
    struct
    {
      struct nfc_cfg **items;
      size_t count;
    } array;
    struct
    {
      char **keys;
      struct nfc_cfg **items;
      size_t count;
    } object;
  } u;
};

struct cfg_parser
{
  const char *cur;
  const char *end;
  int depth;
};

static struct nfc_cfg *
node_new (enum nfc_cfg_type type)
{
  struct nfc_cfg *node = (struct nfc_cfg *) npx_calloc (1, sizeof (*node));

  if (node != NULL)
  {
    node->type = type;
  }
  return node;
}

static void
skip_ws (struct cfg_parser *parser)
{
  while (parser->cur < parser->end
     && (*parser->cur == ' ' || *parser->cur == '\t'
       || *parser->cur == '\n' || *parser->cur == '\r'))
  {
    parser->cur++;
  }
}

static int
text_reserve (char **buffer, size_t *length, size_t *capacity, size_t extra)
{
  size_t need = *length + extra + 1;
  size_t new_capacity;
  char *grown;

  if (*capacity >= need)
  {
    return 0;
  }
  new_capacity = (*capacity == 0) ? 32 : *capacity;
  while (new_capacity < need)
  {
    new_capacity *= 2;
  }
  grown = (char *) npx_realloc (*buffer, new_capacity);
  if (grown == NULL)
  {
    return -1;
  }
  *buffer = grown;
  *capacity = new_capacity;
  return 0;
}

static int
hex4 (struct cfg_parser *parser, unsigned *out_value)
{
  unsigned value = 0;
  int index;

  if (parser->end - parser->cur < 4)
  {
    return -1;
  }
  for (index = 0; index < 4; index++)
  {
    char digit = parser->cur[index];
    unsigned nibble;

    if (digit >= '0' && digit <= '9')
    {
      nibble = (unsigned) (digit - '0');
    }
    else if (digit >= 'a' && digit <= 'f')
    {
      nibble = (unsigned) (digit - 'a') + 10u;
    }
    else if (digit >= 'A' && digit <= 'F')
    {
      nibble = (unsigned) (digit - 'A') + 10u;
    }
    else
    {
      return -1;
    }
    value = value * 16u + nibble;
  }
  parser->cur += 4;
  *out_value = value;
  return 0;
}

static int
utf8_emit (char **buffer, size_t *length, size_t *capacity, unsigned codepoint)
{
  unsigned char bytes[4];
  int count;
  int index;

  if (codepoint <= 0x7Fu)
  {
    bytes[0] = (unsigned char) codepoint;
    count = 1;
  }
  else if (codepoint <= 0x7FFu)
  {
    bytes[0] = (unsigned char) (0xC0u | (codepoint >> 6));
    bytes[1] = (unsigned char) (0x80u | (codepoint & 0x3Fu));
    count = 2;
  }
  else if (codepoint <= 0xFFFFu)
  {
    bytes[0] = (unsigned char) (0xE0u | (codepoint >> 12));
    bytes[1] = (unsigned char) (0x80u | ((codepoint >> 6) & 0x3Fu));
    bytes[2] = (unsigned char) (0x80u | (codepoint & 0x3Fu));
    count = 3;
  }
  else
  {
    bytes[0] = (unsigned char) (0xF0u | (codepoint >> 18));
    bytes[1] = (unsigned char) (0x80u | ((codepoint >> 12) & 0x3Fu));
    bytes[2] = (unsigned char) (0x80u | ((codepoint >> 6) & 0x3Fu));
    bytes[3] = (unsigned char) (0x80u | (codepoint & 0x3Fu));
    count = 4;
  }
  if (text_reserve (buffer, length, capacity, (size_t) count) != 0)
  {
    return -1;
  }
  for (index = 0; index < count; index++)
  {
    (*buffer)[(*length)++] = (char) bytes[index];
  }
  return 0;
}

static int
parse_string (struct cfg_parser *parser, char **out_text)
{
  char *buffer = NULL;
  size_t length = 0;
  size_t capacity = 0;

  *out_text = NULL;
  if (parser->cur >= parser->end || *parser->cur != '"')
  {
    return -1;
  }
  parser->cur++;
  for (;;)
  {
    char c;

    if (parser->cur >= parser->end)
    {
      goto fail;
    }
    c = *parser->cur++;
    if (c == '"')
    {
      if (text_reserve (&buffer, &length, &capacity, 0) != 0)
      {
        goto fail;
      }
      buffer[length] = '\0';
      *out_text = buffer;
      return 0;
    }
    if ((unsigned char) c < 0x20u)
    {
      goto fail;
    }
    if (c != '\\')
    {
      if (text_reserve (&buffer, &length, &capacity, 1) != 0)
      {
        goto fail;
      }
      buffer[length++] = c;
      continue;
    }
    if (parser->cur >= parser->end)
    {
      goto fail;
    }
    c = *parser->cur++;
    switch (c)
    {
    case '"':
    case '\\':
    case '/':
      if (text_reserve (&buffer, &length, &capacity, 1) != 0)
      {
        goto fail;
      }
      buffer[length++] = c;
      break;
    case 'b':
    case 'f':
    case 'n':
    case 'r':
    case 't':
      if (text_reserve (&buffer, &length, &capacity, 1) != 0)
      {
        goto fail;
      }
      buffer[length++] = (c == 'b') ? '\b' : (c == 'f') ? '\f'
               : (c == 'n') ? '\n' : (c == 'r') ? '\r' : '\t';
      break;
    case 'u':
      {
      unsigned codepoint;

      if (hex4 (parser, &codepoint) != 0)
        {
        goto fail;
        }
      if (codepoint >= 0xD800u && codepoint <= 0xDBFFu)
        {
        unsigned low;

        if (parser->end - parser->cur < 2
          || parser->cur[0] != '\\' || parser->cur[1] != 'u')
          {
          goto fail;
          }
        parser->cur += 2;
        if (hex4 (parser, &low) != 0)
          {
          goto fail;
          }
        if (low < 0xDC00u || low > 0xDFFFu)
          {
          goto fail;
          }
        codepoint = 0x10000u + ((codepoint - 0xD800u) << 10)
              + (low - 0xDC00u);
        }
      else if (codepoint >= 0xDC00u && codepoint <= 0xDFFFu)
        {
        goto fail; /* lone low surrogate */
        }
      else if (codepoint == 0u)
        {
        goto fail; /* embedded NUL is unusable through the C API */
        }
      if (utf8_emit (&buffer, &length, &capacity, codepoint) != 0)
        {
        goto fail;
        }
      break;
      }
    default:
      goto fail;
    }
  }
fail:
  npx_free (buffer);
  return -1;
}

static int
number_is_valid (const char *text, size_t length)
{
  size_t index = 0;

  if (length == 0)
  {
    return -1;
  }
  if (text[0] == '-')
  {
    index = 1;
    if (length < 2)
    {
      return -1;
    }
  }
  if (text[index] == '0')
  {
    index++;
    if (index < length && text[index] >= '0' && text[index] <= '9')
    {
      return -1; /* leading zero */
    }
  }
  else if (text[index] >= '1' && text[index] <= '9')
  {
    index++;
    while (index < length && text[index] >= '0' && text[index] <= '9')
    {
      index++;
    }
  }
  else
  {
    return -1;
  }
  if (index < length && text[index] == '.')
  {
    index++;
    if (index >= length || text[index] < '0' || text[index] > '9')
    {
      return -1;
    }
    while (index < length && text[index] >= '0' && text[index] <= '9')
    {
      index++;
    }
  }
  if (index < length && (text[index] == 'e' || text[index] == 'E'))
  {
    index++;
    if (index < length && (text[index] == '+' || text[index] == '-'))
    {
      index++;
    }
    if (index >= length || text[index] < '0' || text[index] > '9')
    {
      return -1;
    }
    while (index < length && text[index] >= '0' && text[index] <= '9')
    {
      index++;
    }
  }
  return (index == length) ? 0 : -1;
}

static int
parse_number (struct cfg_parser *parser, struct nfc_cfg **out_node)
{
  char buffer[CFG_MAX_NUMBER_CHARS + 1];
  size_t length = 0;
  size_t index;
  int integral = 1;
  struct nfc_cfg *node;

  while (parser->cur < parser->end)
  {
    char c = *parser->cur;

    if (!((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.'
      || c == 'e' || c == 'E'))
    {
      break;
    }
    if (length >= CFG_MAX_NUMBER_CHARS)
    {
      return -1;
    }
    buffer[length++] = c;
    parser->cur++;
  }
  buffer[length] = '\0';
  if (number_is_valid (buffer, length) != 0)
  {
    return -1;
  }
  for (index = 0; index < length; index++)
  {
    if (buffer[index] == '.' || buffer[index] == 'e'
      || buffer[index] == 'E')
    {
      integral = 0;
      break;
    }
  }
  if (integral)
  {
    long long value;

    errno = 0;
    value = strtoll (buffer, NULL, 10);
    if (errno != ERANGE)
    {
      node = node_new (NFC_CFG_INT);
      if (node == NULL)
      {
        return -1;
      }
      node->u.integer = (int64_t) value;
      *out_node = node;
      return 0;
    }
    integral = 0; /* out of int64 range: keep as real */
  }
  {
  double value;

  errno = 0;
  value = strtod (buffer, NULL);
  if (errno == ERANGE && value != 0.0)
    {
    return -1; /* overflow (underflow to zero is acceptable) */
    }
  node = node_new (NFC_CFG_REAL);
  if (node == NULL)
    {
    return -1;
    }
  node->u.real = value;
  *out_node = node;
  return 0;
  }
}

static int parse_value (struct cfg_parser *parser, struct nfc_cfg **out_node);

static int
parse_array (struct cfg_parser *parser, struct nfc_cfg **out_node)
{
  struct nfc_cfg *node;
  struct nfc_cfg **items = NULL;
  size_t count = 0;
  size_t capacity = 0;

  node = node_new (NFC_CFG_ARRAY);
  if (node == NULL)
  {
    return -1;
  }
  parser->cur++; /* '[' */
  skip_ws (parser);
  if (parser->cur < parser->end && *parser->cur == ']')
  {
    parser->cur++;
    *out_node = node;
    return 0;
  }
  for (;;)
  {
    struct nfc_cfg *item;

    if (parse_value (parser, &item) != 0)
    {
      goto fail;
    }
    if (count == capacity)
    {
      size_t new_capacity = (capacity == 0) ? 4 : capacity * 2;
      struct nfc_cfg **grown;

      grown = (struct nfc_cfg **) npx_realloc (items,
                           sizeof (*grown)
                           * new_capacity);
      if (grown == NULL)
      {
        nfc_cfg_free (item);
        goto fail;
      }
      items = grown;
      capacity = new_capacity;
    }
    items[count++] = item;
    skip_ws (parser);
    if (parser->cur < parser->end && *parser->cur == ',')
    {
      parser->cur++;
      continue;
    }
    if (parser->cur < parser->end && *parser->cur == ']')
    {
      parser->cur++;
      break;
    }
    goto fail;
  }
  node->u.array.items = items;
  node->u.array.count = count;
  *out_node = node;
  return 0;
fail:
  node->u.array.items = items;
  node->u.array.count = count;
  nfc_cfg_free (node);
  return -1;
}

static int
parse_object (struct cfg_parser *parser, struct nfc_cfg **out_node)
{
  struct nfc_cfg *node;
  char **keys = NULL;
  struct nfc_cfg **items = NULL;
  size_t count = 0;
  size_t capacity = 0;

  node = node_new (NFC_CFG_OBJECT);
  if (node == NULL)
  {
    return -1;
  }
  parser->cur++; /* '{' */
  skip_ws (parser);
  if (parser->cur < parser->end && *parser->cur == '}')
  {
    parser->cur++;
    *out_node = node;
    return 0;
  }
  for (;;)
  {
    char *key;
    struct nfc_cfg *item;

    skip_ws (parser);
    if (parse_string (parser, &key) != 0)
    {
      goto fail;
    }
    skip_ws (parser);
    if (parser->cur >= parser->end || *parser->cur != ':')
    {
      npx_free (key);
      goto fail;
    }
    parser->cur++;
    if (parse_value (parser, &item) != 0)
    {
      npx_free (key);
      goto fail;
    }
    if (count == capacity)
    {
      size_t new_capacity = (capacity == 0) ? 4 : capacity * 2;
      char **grown_keys;
      struct nfc_cfg **grown_items;

      grown_keys =
      (char **) npx_realloc (keys, sizeof (*grown_keys) * new_capacity);
      if (grown_keys == NULL)
      {
        npx_free (key);
        nfc_cfg_free (item);
        goto fail;
      }
      keys = grown_keys;
      grown_items = (struct nfc_cfg **) npx_realloc (items,
                             sizeof (*grown_items)
                             * new_capacity);
      if (grown_items == NULL)
      {
        npx_free (key);
        nfc_cfg_free (item);
        goto fail;
      }
      items = grown_items;
      capacity = new_capacity;
    }
    keys[count] = key;
    items[count] = item;
    count++;
    skip_ws (parser);
    if (parser->cur < parser->end && *parser->cur == ',')
    {
      parser->cur++;
      continue;
    }
    if (parser->cur < parser->end && *parser->cur == '}')
    {
      parser->cur++;
      break;
    }
    goto fail;
  }
  node->u.object.keys = keys;
  node->u.object.items = items;
  node->u.object.count = count;
  *out_node = node;
  return 0;
fail:
  node->u.object.keys = keys;
  node->u.object.items = items;
  node->u.object.count = count;
  nfc_cfg_free (node);
  return -1;
}

static int
parse_value (struct cfg_parser *parser, struct nfc_cfg **out_node)
{
  char c;

  skip_ws (parser);
  if (parser->cur >= parser->end)
  {
    return -1;
  }
  if (parser->depth >= CFG_MAX_DEPTH)
  {
    return -1;
  }
  c = *parser->cur;
  if (c == '{' || c == '[')
  {
    int rc;

    parser->depth++;
    rc = (c == '{') ? parse_object (parser, out_node)
           : parse_array (parser, out_node);
    parser->depth--;
    return rc;
  }
  if (c == '"')
  {
    char *text;
    struct nfc_cfg *node;

    if (parse_string (parser, &text) != 0)
    {
      return -1;
    }
    node = node_new (NFC_CFG_STRING);
    if (node == NULL)
    {
      npx_free (text);
      return -1;
    }
    node->u.text = text;
    *out_node = node;
    return 0;
  }
  if (c == 't' || c == 'f' || c == 'n')
  {
    static const char keyword_true[] = "true";
    static const char keyword_false[] = "false";
    static const char keyword_null[] = "null";
    const char *keyword;
    size_t keyword_length;
    enum nfc_cfg_type type;
    int boolean = 0;
    struct nfc_cfg *node;

    if (c == 't')
    {
      keyword = keyword_true;
      keyword_length = 4;
      type = NFC_CFG_BOOL;
      boolean = 1;
    }
    else if (c == 'f')
    {
      keyword = keyword_false;
      keyword_length = 5;
      type = NFC_CFG_BOOL;
    }
    else
    {
      keyword = keyword_null;
      keyword_length = 4;
      type = NFC_CFG_NULL;
    }
    if ((size_t) (parser->end - parser->cur) < keyword_length
      || memcmp (parser->cur, keyword, keyword_length) != 0)
    {
      return -1;
    }
    parser->cur += keyword_length;
    node = node_new (type);
    if (node == NULL)
    {
      return -1;
    }
    if (type == NFC_CFG_BOOL)
    {
      node->u.boolean = boolean;
    }
    *out_node = node;
    return 0;
  }
  if (c == '-' || (c >= '0' && c <= '9'))
  {
    return parse_number (parser, out_node);
  }
  return -1;
}

int
nfc_cfg_parse (const char *text, size_t length, struct nfc_cfg **out_root)
{
  struct cfg_parser parser;
  struct nfc_cfg *root = NULL;
  int rc;

  if (text == NULL || length == 0 || out_root == NULL)
  {
    return -1;
  }
  *out_root = NULL;
  parser.cur = text;
  parser.end = text + length;
  parser.depth = 0;
  rc = parse_value (&parser, &root);
  if (rc != 0)
  {
    nfc_cfg_free (root);
    return -1;
  }
  skip_ws (&parser);
  if (parser.cur != parser.end)
  {
    nfc_cfg_free (root);
    return -1;
  }
  *out_root = root;
  return 0;
}

void
nfc_cfg_free (struct nfc_cfg *root)
{
  size_t index;

  if (root == NULL)
  {
    return;
  }
  switch (root->type)
  {
  case NFC_CFG_STRING:
    npx_free (root->u.text);
    break;
  case NFC_CFG_ARRAY:
    for (index = 0; index < root->u.array.count; index++)
    {
      nfc_cfg_free (root->u.array.items[index]);
    }
    npx_free (root->u.array.items);
    break;
  case NFC_CFG_OBJECT:
    for (index = 0; index < root->u.object.count; index++)
    {
      npx_free (root->u.object.keys[index]);
      nfc_cfg_free (root->u.object.items[index]);
    }
    npx_free (root->u.object.keys);
    npx_free (root->u.object.items);
    break;
  default:
    break;
  }
  npx_free (root);
}

static const struct nfc_cfg *
object_find (const struct nfc_cfg *node, const char *key, size_t key_length)
{
  size_t index;

  for (index = 0; index < node->u.object.count; index++)
  {
    const char *candidate = node->u.object.keys[index];

    if (strlen (candidate) == key_length
      && memcmp (candidate, key, key_length) == 0)
    {
      return node->u.object.items[index];
    }
  }
  return NULL;
}

int
nfc_cfg_lookup (const struct nfc_cfg *root, const char *path,
        struct nfc_cfg **out_node)
{
  const struct nfc_cfg *node = root;
  const char *cursor = path;

  if (root == NULL || path == NULL || out_node == NULL)
  {
    return -1;
  }
  *out_node = NULL;
  if (cursor[0] == '\0')
  {
    *out_node = (struct nfc_cfg *) root;
    return 0;
  }
  while (*cursor != '\0')
  {
    if (*cursor == '[')
    {
      size_t index = 0;
      int has_index = 0;

      cursor++;
      while (*cursor >= '0' && *cursor <= '9')
      {
        index = index * 10u + (size_t) (*cursor - '0');
        cursor++;
        has_index = 1;
      }
      if (!has_index || *cursor != ']')
      {
        return -1;
      }
      cursor++;
      if (node == NULL || node->type != NFC_CFG_ARRAY
        || index >= node->u.array.count)
      {
        return -1;
      }
      node = node->u.array.items[index];
    }
    else
    {
      const char *key_start;
      size_t key_length;

      if (*cursor == '.')
      {
        cursor++;
      }
      key_start = cursor;
      while (*cursor != '\0' && *cursor != '.' && *cursor != '[')
      {
        cursor++;
      }
      key_length = (size_t) (cursor - key_start);
      if (key_length == 0 || node == NULL
        || node->type != NFC_CFG_OBJECT)
      {
        return -1;
      }
      node = object_find (node, key_start, key_length);
      if (node == NULL)
      {
        return -1;
      }
    }
  }
  *out_node = (struct nfc_cfg *) node;
  return 0;
}

int
nfc_cfg_get_bool (const struct nfc_cfg *node, int *out_value)
{
  if (node == NULL || out_value == NULL || node->type != NFC_CFG_BOOL)
  {
    return -1;
  }
  *out_value = node->u.boolean;
  return 0;
}

int
nfc_cfg_get_int64 (const struct nfc_cfg *node, int64_t *out_value)
{
  if (node == NULL || out_value == NULL)
  {
    return -1;
  }
  if (node->type == NFC_CFG_INT)
  {
    *out_value = node->u.integer;
    return 0;
  }
  if (node->type == NFC_CFG_REAL)
  {
    *out_value = (int64_t) node->u.real;
    return 0;
  }
  return -1;
}

int
nfc_cfg_get_real (const struct nfc_cfg *node, double *out_value)
{
  if (node == NULL || out_value == NULL)
  {
    return -1;
  }
  if (node->type == NFC_CFG_REAL)
  {
    *out_value = node->u.real;
    return 0;
  }
  if (node->type == NFC_CFG_INT)
  {
    *out_value = (double) node->u.integer;
    return 0;
  }
  return -1;
}

int
nfc_cfg_get_string (const struct nfc_cfg *node, const char **out_text)
{
  if (node == NULL || out_text == NULL || node->type != NFC_CFG_STRING)
  {
    return -1;
  }
  *out_text = node->u.text;
  return 0;
}

enum nfc_cfg_type
nfc_cfg_type (const struct nfc_cfg *node)
{
  /* A missing node reports NFC_CFG_NULL; callers distinguish NULL from a
   * real JSON null through the lookup result, not through this accessor. */
  return (node != NULL) ? node->type : NFC_CFG_NULL;
}

const char *
nfc_cfg_type_name (enum nfc_cfg_type type)
{
  switch (type)
  {
  case NFC_CFG_NULL:
    return "null";
  case NFC_CFG_BOOL:
    return "bool";
  case NFC_CFG_INT:
    return "int";
  case NFC_CFG_REAL:
    return "real";
  case NFC_CFG_STRING:
    return "string";
  case NFC_CFG_ARRAY:
    return "array";
  case NFC_CFG_OBJECT:
    return "object";
  default:
    break;
  }
  return "invalid";
}

size_t
nfc_cfg_array_count (const struct nfc_cfg *node)
{
  if (node == NULL || node->type != NFC_CFG_ARRAY)
  {
    return 0;
  }
  return node->u.array.count;
}

int
nfc_cfg_array_get (const struct nfc_cfg *node, size_t index,
           struct nfc_cfg **out_item)
{
  if (node == NULL || out_item == NULL || node->type != NFC_CFG_ARRAY
    || index >= node->u.array.count)
  {
    return -1;
  }
  *out_item = node->u.array.items[index];
  return 0;
}

size_t
nfc_cfg_object_count (const struct nfc_cfg *node)
{
  if (node == NULL || node->type != NFC_CFG_OBJECT)
  {
    return 0;
  }
  return node->u.object.count;
}

int
nfc_cfg_object_get (const struct nfc_cfg *node, const char *key,
          struct nfc_cfg **out_item)
{
  const struct nfc_cfg *found;

  if (node == NULL || out_item == NULL || key == NULL
    || node->type != NFC_CFG_OBJECT)
  {
    return -1;
  }
  found = object_find (node, key, strlen (key));
  if (found == NULL)
  {
    return -1;
  }
  *out_item = (struct nfc_cfg *) found;
  return 0;
}
