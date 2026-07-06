#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#define VK_USE_PLATFORM_WIN32_KHR 1
#include <vulkan/vulkan.h>
#include "obj/generated/brovvulk_gen.h"
#include "obj/generated/brovvulk_gen_protos.h"

#define IOCTL_BROVVULK_GEN 0x80002004u

#if defined(_MSC_VER)
#define BVK_TLS __declspec(thread)
#else
#define BVK_TLS __thread
#endif

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static HANDLE brov_dev(void)
{
    if (g_dev == INVALID_HANDLE_VALUE)
    {
        g_dev = CreateFileW(L"\\\\.\\BrovVulk",
                            GENERIC_READ | GENERIC_WRITE,
                            0, NULL, OPEN_EXISTING, 0, NULL);
    }
    return g_dev;
}

static const VkExtensionProperties g_InstanceExtensions[] =
{
    { "VK_KHR_surface",        25 },
    { "VK_KHR_win32_surface",   6 },
};

VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceExtensionProperties(
    const char *pLayerName, uint32_t *pPropertyCount, VkExtensionProperties *pProperties)
{
    if (pLayerName != NULL)
    {
        if (pPropertyCount)
            *pPropertyCount = 0;
        return VK_SUCCESS;
    }

    uint32_t total = (uint32_t)(sizeof(g_InstanceExtensions) / sizeof(g_InstanceExtensions[0]));
    if (pProperties == NULL)
    {
        if (pPropertyCount)
            *pPropertyCount = total;
        return VK_SUCCESS;
    }

    uint32_t avail = pPropertyCount ? *pPropertyCount : 0;
    uint32_t copy = avail < total ? avail : total;
    if (copy > 0)
        memcpy(pProperties, g_InstanceExtensions, copy * sizeof(VkExtensionProperties));
    if (pPropertyCount)
        *pPropertyCount = copy;
    return copy < total ? VK_INCOMPLETE : VK_SUCCESS;
}

VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateInstanceLayerProperties(
    uint32_t *pPropertyCount, VkLayerProperties *pProperties)
{
    (void)pProperties;
    if (pPropertyCount)
        *pPropertyCount = 0;
    return VK_SUCCESS;
}

static const VkExtensionProperties g_DeviceExtensions[] =
{
    { "VK_KHR_swapchain", 70 },
};

VKAPI_ATTR VkResult VKAPI_CALL vkEnumerateDeviceExtensionProperties(
    VkPhysicalDevice physicalDevice, const char *pLayerName,
    uint32_t *pPropertyCount, VkExtensionProperties *pProperties)
{
    (void)physicalDevice;
    if (pLayerName != NULL)
    {
        if (pPropertyCount)
            *pPropertyCount = 0;
        return VK_SUCCESS;
    }

    uint32_t total = (uint32_t)(sizeof(g_DeviceExtensions) / sizeof(g_DeviceExtensions[0]));
    if (pProperties == NULL)
    {
        if (pPropertyCount)
            *pPropertyCount = total;
        return VK_SUCCESS;
    }

    uint32_t avail = pPropertyCount ? *pPropertyCount : 0;
    uint32_t copy = avail < total ? avail : total;
    if (copy > 0)
        memcpy(pProperties, g_DeviceExtensions, copy * sizeof(VkExtensionProperties));
    if (pPropertyCount)
        *pPropertyCount = copy;
    return copy < total ? VK_INCOMPLETE : VK_SUCCESS;
}

#define BVK_HDR 8u

static BVK_TLS unsigned char *bvk_rq;
static BVK_TLS unsigned int bvk_rqcap;
static BVK_TLS unsigned int bvk_rqlen;

static void bvk_rq_grow(unsigned int need)
{
    if (need <= bvk_rqcap)
        return;
    unsigned int nc = bvk_rqcap ? bvk_rqcap : 8192u;
    while (nc < need)
        nc *= 2u;
    unsigned char *nb = (unsigned char *)realloc(bvk_rq, nc);
    if (nb) { bvk_rq = nb; bvk_rqcap = nc; }
}

static void bvk_rq_reset(void)
{
    bvk_rq_grow(BVK_HDR);
    bvk_rqlen = BVK_HDR;
}

static void bvk_w_u32(uint32_t v)
{
    bvk_rq_grow(bvk_rqlen + 4);
    memcpy(bvk_rq + bvk_rqlen, &v, 4);
    bvk_rqlen += 4;
}

static void bvk_w_u64(uint64_t v)
{
    bvk_rq_grow(bvk_rqlen + 8);
    memcpy(bvk_rq + bvk_rqlen, &v, 8);
    bvk_rqlen += 8;
}

static void bvk_w_bytes(const void *s, unsigned int len)
{
    bvk_rq_grow(bvk_rqlen + len);
    if (len)
        memcpy(bvk_rq + bvk_rqlen, s, len);
    bvk_rqlen += len;
}

static int bvk_rq_send(uint32_t cmd, void *out, uint32_t outCap, uint32_t *outLen)
{
    HANDLE h = brov_dev();
    if (h == INVALID_HANDLE_VALUE)
        return VK_ERROR_INITIALIZATION_FAILED;

    uint32_t plen = bvk_rqlen - BVK_HDR;
    memcpy(bvk_rq + 0, &cmd, 4);
    memcpy(bvk_rq + 4, &plen, 4);

    DWORD ret = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_BROVVULK_GEN, bvk_rq, bvk_rqlen, out, outCap, &ret, NULL);
    if (!ok || ret < 4)
        return VK_ERROR_INITIALIZATION_FAILED;

    if (ret > outCap)
        return VK_ERROR_OUT_OF_HOST_MEMORY;

    if (outLen)
        *outLen = ret;
    int vkres;
    memcpy(&vkres, out, 4);
    return vkres;
}

#include "obj/generated/brovvulk_structs.h"

static void bvk_ser_struct(int sid, const unsigned char *s)
{
    const BvkM *mm = bvk_structs[sid];
    int mc = bvk_struct_counts[sid];
    for (int i = 0; i < mc; i++)
    {
        const BvkM *d = &mm[i];
        const unsigned char *fp = s + d->offset;
        switch (d->kind)
        {
        case 0:
            bvk_w_bytes(fp, (unsigned int)d->size);
            break;
        case 1:
            bvk_w_u32((uint32_t)(uintptr_t)(*(void *const *)fp));
            break;
        case 2:
            bvk_ser_struct(d->sub, fp);
            break;
        case 3:
        {
            const void *p = *(const void *const *)fp;
            if (p) { bvk_w_u32(1); bvk_ser_struct(d->sub, (const unsigned char *)p); }
            else bvk_w_u32(0);
            break;
        }
        case 4:
        {
            const void *p = *(const void *const *)fp;
            uint32_t n = *(const uint32_t *)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); for (uint32_t k = 0; k < n; k++) bvk_ser_struct(d->sub, (const unsigned char *)p + (size_t)k * bvk_struct_sizes[d->sub]); }
            else bvk_w_u32(0);
            break;
        }
        case 5:
        {
            const void *const *p = *(const void *const *const *)fp;
            uint32_t n = *(const uint32_t *)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); for (uint32_t k = 0; k < n; k++) bvk_w_u32((uint32_t)(uintptr_t)p[k]); }
            else bvk_w_u32(0);
            break;
        }
        case 6:
        {
            const void *p = *(const void *const *)fp;
            uint32_t n = *(const uint32_t *)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); bvk_w_bytes(p, n * (unsigned int)d->size); }
            else bvk_w_u32(0);
            break;
        }
        case 7:
        {
            const char *p = *(const char *const *)fp;
            if (p) { uint32_t l = (uint32_t)strlen(p) + 1; bvk_w_u32(l); bvk_w_bytes(p, l); }
            else bvk_w_u32(0);
            break;
        }
        case 8:
        {
            const char *const *p = *(const char *const *const *)fp;
            uint32_t n = *(const uint32_t *)(s + d->lenOffset);
            if (p) { bvk_w_u32(n); for (uint32_t k = 0; k < n; k++) { uint32_t l = (uint32_t)strlen(p[k]) + 1; bvk_w_u32(l); bvk_w_bytes(p[k], l); } }
            else bvk_w_u32(0);
            break;
        }
        case 9:
            bvk_w_u32((*(const void *const *)fp) ? 1 : 0);
            break;
        case 11:
        {
            const void *p = *(const void *const *)fp;
            uint32_t n = (uint32_t)(*(const size_t *)(s + d->lenOffset));
            if (p) { bvk_w_u32(n); bvk_w_bytes(p, n); }
            else bvk_w_u32(0);
            break;
        }
        default:
            break;
        }
    }
}

#define BVK_BATCH_ID 0xFFFFFFFEu
#define BVK_BATCH_LIMIT 900000u

static BVK_TLS unsigned char *bvk_rec;
static BVK_TLS unsigned int bvk_reccap;
static BVK_TLS unsigned int bvk_reclen;
static BVK_TLS unsigned int bvk_reccount;

static void bvk_rec_grow(unsigned int need)
{
    if (need <= bvk_reccap)
        return;
    unsigned int nc = bvk_reccap ? bvk_reccap : 65536u;
    while (nc < need)
        nc *= 2u;
    unsigned char *nb = (unsigned char *)realloc(bvk_rec, nc);
    if (nb) { bvk_rec = nb; bvk_reccap = nc; }
}

static void bvk_rec_begin(void)
{
    bvk_rec_grow(BVK_HDR + 4);
    bvk_reclen = BVK_HDR + 4;
    bvk_reccount = 0;
}

static int bvk_rec_dispatch(void)
{
    uint32_t plen = bvk_reclen - BVK_HDR;
    uint32_t cmd = BVK_BATCH_ID;
    memcpy(bvk_rec + 0, &cmd, 4);
    memcpy(bvk_rec + 4, &plen, 4);
    memcpy(bvk_rec + BVK_HDR, &bvk_reccount, 4);
    HANDLE h = brov_dev();
    int r = VK_ERROR_INITIALIZATION_FAILED;
    if (h != INVALID_HANDLE_VALUE)
    {
        unsigned char obuf[32];
        DWORD ret = 0;
        BOOL ok = DeviceIoControl(h, IOCTL_BROVVULK_GEN, bvk_rec, bvk_reclen, obuf, sizeof(obuf), &ret, NULL);
        if (ok && ret >= 4)
            memcpy(&r, obuf, 4);
    }
    bvk_reclen = BVK_HDR + 4;
    bvk_reccount = 0;
    return r;
}

static void bvk_rec_append(uint32_t id)
{
    unsigned int args = bvk_rqlen - BVK_HDR;
    if (bvk_reccount != 0 && (uint64_t)bvk_reclen + 4 + args > BVK_BATCH_LIMIT)
        bvk_rec_dispatch();
    bvk_rec_grow(bvk_reclen + 4 + args);
    memcpy(bvk_rec + bvk_reclen, &id, 4);
    bvk_reclen += 4;
    memcpy(bvk_rec + bvk_reclen, bvk_rq + BVK_HDR, args);
    bvk_reclen += args;
    bvk_reccount++;
}

static int bvk_rec_flush(void)
{
    return bvk_rec_dispatch();
}

#include "obj/generated/brovvulk_gen.c"

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetInstanceProcAddr(VkInstance instance, const char *pName)
{
    (void)instance;
    if (!pName)
        return NULL;

#define M(n)                                        \
    if (strcmp(pName, #n) == 0)                      \
    return (PFN_vkVoidFunction)n

    M(vkGetInstanceProcAddr);
    M(vkGetDeviceProcAddr);
    M(vkEnumerateInstanceExtensionProperties);
    M(vkEnumerateInstanceLayerProperties);
    M(vkEnumerateDeviceExtensionProperties);
#include "obj/generated/brovvulk_gen_procs.inc"
#undef M

    return NULL;
}

VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL vkGetDeviceProcAddr(VkDevice device, const char *pName)
{
    (void)device;
    return vkGetInstanceProcAddr(VK_NULL_HANDLE, pName);
}
