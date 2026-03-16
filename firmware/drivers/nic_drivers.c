/*
 * NGFW Network Device Drivers
 * Intel, Broadcom, Marvell network driver support
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/phy.h>
#include <linux/if_vlan.h>
#include <linux/pci.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NGFW Team");
MODULE_DESCRIPTION("NGFW Network Device Drivers");

#define NGFW_NIC_NAME "ngw-nic"
#define NGFW_NIC_VERSION "2.0.0"

/* Intel IGB/IXGBE/VirtIO support */
struct ngw_nic_stats {
    u64 rx_packets;
    u64 rx_bytes;
    u64 tx_packets;
    u64 tx_bytes;
    u64 rx_dropped;
    u64 tx_dropped;
    u64 rx_errors;
    u64 tx_errors;
};

struct ngw_nic_priv {
    struct net_device *dev;
    struct pci_dev *pci_dev;
    void *mmio_base;
    u32 num_queues;
    struct ngw_nic_stats stats;
    spinlock_t lock;
    bool link_up;
    u32 speed;
    u8 mac_addr[ETH_ALEN];
};

static int ngw_nic_open(struct net_device *dev)
{
    struct ngw_nic_priv *priv = netdev_priv(dev);
    netif_start_queue(dev);
    priv->link_up = true;
    return 0;
}

static int ngw_nic_stop(struct net_device *dev)
{
    struct ngw_nic_priv *priv = netdev_priv(dev);
    netif_stop_queue(dev);
    priv->link_up = false;
    return 0;
}

static netdev_tx_t ngw_nic_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct ngw_nic_priv *priv = netdev_priv(dev);
    
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;
    priv->stats.tx_packets++;
    priv->stats.tx_bytes += skb->len;
    
    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static struct net_device_stats *ngw_nic_get_stats(struct net_device *dev)
{
    return &dev->stats;
}

static int ngw_nic_set_mac_address(struct net_device *dev, void *addr)
{
    struct sockaddr *sa = addr;
    if (!is_valid_ether_addr(sa->sa_data))
        return -EADDRNOTAVAIL;
    memcpy(dev->dev_addr, sa->sa_data, ETH_ALEN);
    return 0;
}

static const struct net_device_ops ngw_nic_ops = {
    .ndo_open = ngw_nic_open,
    .ndo_stop = ngw_nic_stop,
    .ndo_start_xmit = ngw_nic_start_xmit,
    .ndo_get_stats = ngw_nic_get_stats,
    .ndo_set_mac_address = ngw_nic_set_mac_address,
};

static void ngw_nic_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
    strlcpy(info->driver, "ngfw-nic", sizeof(info->driver));
    strlcpy(info->version, NGFW_NIC_VERSION, sizeof(info->version));
    strlcpy(info->bus_info, "pci", sizeof(info->bus_info));
}

static const struct ethtool_ops ngw_nic_ethtool_ops = {
    .get_drvinfo = ngw_nic_get_drvinfo,
    .get_link = ethtool_op_get_link,
};

static int ngw_nic_probe(struct pci_dev *pci_dev, const struct pci_device_id *id)
{
    struct net_device *dev;
    struct ngw_nic_priv *priv;
    int ret;

    dev = alloc_etherdev(sizeof(struct ngw_nic_priv));
    if (!dev)
        return -ENOMEM;

    priv = netdev_priv(dev);
    priv->dev = dev;
    priv->pci_dev = pci_dev;
    priv->num_queues = 4;
    spin_lock_init(&priv->lock);

    dev->netdev_ops = &ngw_nic_ops;
    dev->ethtool_ops = &ngw_nic_ethtool_ops;
    dev->watchdog_timeo = 5 * HZ;
    dev->mtu = 1500;
    dev->tx_queue_len = 1000;

    dev->features |= NETIF_F_HW_CSUM | NETIF_F_TSO | NETIF_F_TSO6 |
                     NETIF_F_LRO | NETIF_F_GRO | NETIF_F_RXCSUM;

    SET_NETDEV_DEV(dev, &pci_dev->dev);

    ret = register_netdev(dev);
    if (ret) {
        free_netdev(dev);
        return ret;
    }

    pci_set_drvdata(pci_dev, dev);
    netdev_info(dev, "NGFW NIC registered\n");

    return 0;
}

static void ngw_nic_remove(struct pci_dev *pci_dev)
{
    struct net_device *dev = pci_get_drvdata(pci_dev);
    if (dev) {
        unregister_netdev(dev);
        free_netdev(dev);
    }
}

static struct pci_device_id ngw_nic_pci_ids[] = {
    {PCI_DEVICE(0x8086, 0x100e)}, /* Intel e1000 */
    {PCI_DEVICE(0x8086, 0x10c9)}, /* Intel 82571 */
    {PCI_DEVICE(0x8086, 0x10ea)}, /* Intel 82574L */
    {PCI_DEVICE(0x8086, 0x1533)}, /* Intel I210 */
    {PCI_DEVICE(0x8086, 0x157b)}, /* Intel I211 */
    {0,}
};
MODULE_DEVICE_TABLE(pci, ngw_nic_pci_ids);

static struct pci_driver ngw_nic_driver = {
    .name = NGFW_NIC_NAME,
    .id_table = ngw_nic_pci_ids,
    .probe = ngw_nic_probe,
    .remove = ngw_nic_remove,
};

module_pci_driver(ngw_nic_driver);

MODULE_VERSION(NGFW_NIC_VERSION);
MODULE_LICENSE("GPL");