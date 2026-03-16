/*
 * DPDK NGFW Kernel Module
 * Provides kernel interface for DPDK userspace packet processing
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define DPDK_KMOD_NAME "ngfw_dpdk"
#define DPDK_KMOD_VERSION "2.0.0"

#define MAX_QUEUES 16
#define MAX_PORTS 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NGFW Team");
MODULE_DESCRIPTION("DPDK Kernel Interface for NGFW");
MODULE_VERSION(DPDK_KMOD_VERSION);

struct dpdk_queue {
    struct net_device *dev;
    u16 queue_id;
    u16 ring_size;
    void *rx_ring;
    void *tx_ring;
    bool enabled;
};

struct dpdk_port {
    struct net_device *netdev;
    struct pci_dev *pci_dev;
    u16 port_id;
    u16 num_queues;
    struct dpdk_queue rx_queues[MAX_QUEUES];
    struct dpdk_queue tx_queues[MAX_QUEUES];
    u64 stats.rx_packets;
    u64 stats.rx_bytes;
    u64 stats.tx_packets;
    u64 stats.tx_bytes;
    u64 stats.rx_dropped;
    u64 stats.tx_dropped;
    struct list_head list;
};

static LIST_HEAD(dpdk_ports);
static int dpdk_major;
static struct class *dpdk_class;
static struct device *dpdk_device;
static struct cdev dpdk_cdev;

static int dpdk_port_count = 0;

static int dpdk_netdev_open(struct net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}

static int dpdk_netdev_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    return 0;
}

static netdev_tx_t dpdk_netdev_start_xmit(struct sk_buff *skb,
                                            struct net_device *dev)
{
    struct dpdk_port *port = netdev_priv(dev);

    if (!skb)
        return NETDEV_TX_OK;

    port->stats.tx_packets++;
    port->stats.tx_bytes += skb->len;

    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static struct net_device_stats *dpdk_netdev_get_stats(struct net_device *dev)
{
    struct dpdk_port *port = netdev_priv(dev);
    static struct net_device_stats stats;

    stats.rx_packets = port->stats.rx_packets;
    stats.rx_bytes = port->stats.rx_bytes;
    stats.tx_packets = port->stats.tx_packets;
    stats.tx_bytes = port->stats.tx_bytes;
    stats.rx_dropped = port->stats.rx_dropped;
    stats.tx_dropped = port->stats.tx_dropped;

    return &stats;
}

static int dpdk_netdev_set_mac_address(struct net_device *dev, void *addr)
{
    struct sockaddr *sa = addr;
    if (!is_valid_ether_addr(sa->sa_data))
        return -EADDRNOTAVAIL;
    memcpy(dev->dev_addr, sa->sa_data, ETH_ALEN);
    return 0;
}

static int dpdk_netdev_change_mtu(struct net_device *dev, int new_mtu)
{
    if (new_mtu < 68 || new_mtu > 9000)
        return -EINVAL;
    dev->mtu = new_mtu;
    return 0;
}

static const struct net_device_ops dpdk_netdev_ops = {
    .ndo_open = dpdk_netdev_open,
    .ndo_stop = dpdk_netdev_stop,
    .ndo_start_xmit = dpdk_netdev_start_xmit,
    .ndo_get_stats = dpdk_netdev_get_stats,
    .ndo_change_mtu = dpdk_netdev_change_mtu,
    .ndo_set_mac_address = dpdk_netdev_set_mac_address,
};

static void dpdk_get_drvinfo(struct net_device *dev,
                              struct ethtool_drvinfo *info)
{
    strlcpy(info->driver, "ngfw-dpdk", sizeof(info->driver));
    strlcpy(info->version, DPDK_KMOD_VERSION, sizeof(info->version));
    strlcpy(info->bus_info, "virtual", sizeof(info->bus_info));
}

static const struct ethtool_ops dpdk_ethtool_ops = {
    .get_drvinfo = dpdk_get_drvinfo,
};

static void dpdk_setup_netdev(struct net_device *dev)
{
    dev->netdev_ops = &dpdk_netdev_ops;
    dev->ethtool_ops = &dpdk_ethtool_ops;
    dev->watchdog_timeo = 5 * HZ;
    dev->mtu = 1500;
    dev->tx_queue_len = 1000;
    dev->flags = IFF_BONDING | IFF_SLAVE;
    dev->features |= NETIF_F_HW_CSUM | NETIF_F_TSO | NETIF_F_TSO6 |
                     NETIF_F_LRO | NETIF_F_GRO;
}

static struct dpdk_port *dpdk_create_port(struct pci_dev *pci)
{
    struct net_device *netdev;
    struct dpdk_port *port;
    int err;
    int i;

    netdev = alloc_netdev_mq(sizeof(struct dpdk_port), "dpdk%d",
                              NET_NAME_UNKNOWN, dpdk_setup_netdev, MAX_QUEUES);
    if (!netdev) {
        pr_err("dpdk: failed to allocate netdev\n");
        return NULL;
    }

    port = netdev_priv(netdev);
    port->netdev = netdev;
    port->pci_dev = pci;
    port->port_id = dpdk_port_count++;
    port->num_queues = 1;

    for (i = 0; i < MAX_QUEUES; i++) {
        port->rx_queues[i].dev = netdev;
        port->tx_queues[i].dev = netdev;
    }

    SET_NETDEV_DEV(netdev, &pci->dev);

    err = register_netdev(netdev);
    if (err) {
        pr_err("dpdk: failed to register netdev: %d\n", err);
        free_netdev(netdev);
        return NULL;
    }

    list_add_tail(&port->list, &dpdk_ports);
    pr_info("dpdk: created port %d (%s)\n", port->port_id, netdev->name);

    return port;
}

static int dpdk_probe(struct pci_dev *pci, const struct pci_device_id *id)
{
    struct dpdk_port *port;

    pr_info("dpdk: probing device %04x:%04x\n", pci->vendor, pci->device);

    port = dpdk_create_port(pci);
    if (!port)
        return -ENOMEM;

    pci_set_drvdata(pci, port);
    return 0;
}

static void dpdk_remove(struct pci_dev *pci)
{
    struct dpdk_port *port = pci_get_drvdata(pci);

    if (port) {
        unregister_netdev(port->netdev);
        list_del(&port->list);
        free_netdev(port->netdev);
    }
}

static struct pci_device_id dpdk_pci_ids[] = {
    {PCI_DEVICE(0x8086, 0x100e)},
    {PCI_DEVICE(0x8086, 0x10c9)},
    {PCI_DEVICE(0x8086, 0x10ea)},
    {PCI_DEVICE(0x8086, 0x1533)},
    {0,}
};
MODULE_DEVICE_TABLE(pci, dpdk_pci_ids);

static struct pci_driver dpdk_pci_driver = {
    .name = DPDK_KMOD_NAME,
    .id_table = dpdk_pci_ids,
    .probe = dpdk_probe,
    .remove = dpdk_remove,
};

static long dpdk_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct dpdk_port *port;
    int ret = 0;

    switch (cmd) {
    case 0: /* Get port info */
        list_for_each_entry(port, &dpdk_ports, list) {
            if (port->port_id == (int)arg)
                return (long)port;
        }
        ret = -ENODEV;
        break;

    case 1: /* Enable queue */
        break;

    case 2: /* Disable queue */
        break;

    default:
        ret = -ENOTTY;
    }

    return ret;
}

static int dpdk_mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned long pfn;
    size_t size = vma->vm_end - vma->vm_start;

    if (size > 256 * 1024 * 1024)
        return -EINVAL;

    pfn = vmalloc_to_pfn((void *)vma->vm_start);
    if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot))
        return -EAGAIN;

    return 0;
}

static int dpdk_open(struct inode *inode, struct file *filp)
{
    return 0;
}

static int dpdk_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static const struct file_operations dpdk_fops = {
    .owner = THIS_MODULE,
    .open = dpdk_open,
    .release = dpdk_release,
    .unlocked_ioctl = dpdk_ioctl,
    .mmap = dpdk_mmap,
};

static int __init dpdk_mod_init(void)
{
    dev_t dev;
    int ret;

    pr_info("DPDK NGFW module: %s\n", DPDK_KMOD_VERSION);

    ret = alloc_chrdev_region(&dev, 0, 1, DPDK_KMOD_NAME);
    if (ret < 0) {
        pr_err("dpdk: failed to allocate chrdev\n");
        return ret;
    }
    dpdk_major = MAJOR(dev);

    cdev_init(&dpdk_cdev, &dpdk_fops);
    dpdk_cdev.owner = THIS_MODULE;

    ret = cdev_add(&dpdk_cdev, dev, 1);
    if (ret < 0) {
        pr_err("dpdk: failed to add cdev\n");
        goto err_cdev;
    }

    dpdk_class = class_create(THIS_MODULE, DPDK_KMOD_NAME);
    if (IS_ERR(dpdk_class)) {
        pr_err("dpdk: failed to create class\n");
        goto err_class;
    }

    dpdk_device = device_create(dpdk_class, NULL, dev, NULL, DPDK_KMOD_NAME);
    if (IS_ERR(dpdk_device)) {
        pr_err("dpdk: failed to create device\n");
        goto err_device;
    }

    ret = pci_register_driver(&dpdk_pci_driver);
    if (ret < 0) {
        pr_err("dpdk: failed to register pci driver\n");
        goto err_pci;
    }

    pr_info("dpdk: module loaded successfully\n");
    return 0;

err_pci:
    device_destroy(dpdk_class, dev);
err_device:
    class_destroy(dpdk_class);
err_class:
    cdev_del(&dpdk_cdev);
err_cdev:
    unregister_chrdev_region(dev, 1);
    return ret;
}

static void __exit dpdk_mod_exit(void)
{
    dev_t dev = MKDEV(dpdk_major, 0);

    pci_unregister_driver(&dpdk_pci_driver);
    device_destroy(dpdk_class, dev);
    class_destroy(dpdk_class);
    cdev_del(&dpdk_cdev);
    unregister_chrdev_region(dev, 1);

    pr_info("dpdk: module unloaded\n");
}

module_init(dpdk_mod_init);
module_exit(dpdk_mod_exit);