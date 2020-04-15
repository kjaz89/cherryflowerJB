/*
 * Copyright 2013-2016, iH8sn0w. <iH8sn0w@iH8sn0w.com>
 *
 * This file is part of iBoot32Patcher.
 *
 * iBoot32Patcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * iBoot32Patcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with iBoot32Patcher.  If not, see <http://www.gnu.org/licenses/>.
 */

/* iBoot32Patcher
 *
 * Universal 32-bit iBoot patcher for iPhone OS 2.0 --> iOS 10
 *
 * Build:
 * clang iBoot32Patcher.c finders.c functions.c patchers.c -Wno-multichar -I. -o iBoot32Patcher
 *
 * Usage:
 * ./iBoot32Patcher iBoot.n49.RELEASE.dfu.decrypted iBoot.n49.RELEASE.dfu.patched --rsa
 * ./iBoot32Patcher iBoot.n49.RELEASE.dfu.decrypted iBoot.n49.RELEASE.dfu.patched --rsa --debug -b "cs_enforcement_disable=1 -v"
 * ./iBoot32Patcher iBoot.n49.RELEASE.dfu.decrypted iBoot.n49.RELEASE.dfu.patched --rsa --debug -b "cs_enforcement_disable=1" -c "ticket" 0x80000000
 * ./iBoot32Patcher iBoot.n49.RELEASE.dfu.decrypted iBoot.n49.RELEASE.dfu.patched --rsa -c "ticket" 0x80000000
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "include/arm32_defs.h"
#include "include/finders.h"
#include "include/functions.h"
#include "include/iBoot32Patcher.h"
#include "include/patchers.h"

#include "finders.c"
#include "functions.c"
#include "patchers.c"

#define HAS_ARG(x,y) (!strcmp(argv[i], x) && (i + y) < argc)

int iBoot32Patcher(void* ibot, size_t len,
                   bool rsa_patch,
                   bool debug_patch,
                   bool boot_partition_patch, int boot_partition_9,
                   bool boot_ramdisk_patch,
                   bool setenv_patch,
                   bool i433_patch,
                   bool logo_patch,
                   bool logo4_patch,
                   char* custom_boot_args
                   ){
    
	int ret = 0;
	FILE* fp = NULL;
	uint32_t cmd_handler_ptr = 0;
	char* cmd_handler_str = NULL;
	bool env_boot_args = false;
    bool ticket_patch = false;
    bool remote_patch = false;
    bool local_patch = false;
    bool kaslr_patch = false;
    char* custom_color = NULL;
	struct iboot_img iboot_in;
	memset(&iboot_in, 0, sizeof(iboot_in));

	printf("%s: Starting...\n", __FUNCTION__);

    iboot_in.len = len;
    iboot_in.buf = (void*)malloc(iboot_in.len);
    memcpy(iboot_in.buf, ibot, len);
    
	uint32_t image_magic = *(uint32_t*)iboot_in.buf;
	
	if(image_magic == IMAGE3_MAGIC) {
		printf("%s: The supplied image appears to be in an img3 container. Please ensure that the image is decrypted and that the img3 header is stripped.\n", __FUNCTION__);
		free(iboot_in.buf);
		return -1;
	}

	if(image_magic != IBOOT32_RESET_VECTOR_BYTES) {
		printf("%s: The supplied image is not a valid 32-bit iBoot.\n", __FUNCTION__);
		free(iboot_in.buf);
		return -1;
	}

	const char* iboot_vers_str = (iboot_in.buf + IBOOT_VERS_STR_OFFSET);

	iboot_in.VERS = atoi(iboot_vers_str);
	if(!iboot_in.VERS) {
		printf("%s: No iBoot version found!\n", __FUNCTION__);
		free(iboot_in.buf);
		return -1;
	}
    
	printf("%s: iBoot-%d inputted.\n", __FUNCTION__, iboot_in.VERS);
		/* Check to see if the loader has a kernel load routine before trying to apply custom boot args + debug-enabled override. */
	if(has_kernel_load(&iboot_in)) {
		if(custom_boot_args) {
			ret = patch_boot_args(&iboot_in, custom_boot_args);
			if(!ret) {
				printf("%s: Error doing patch_boot_args()!\n", __FUNCTION__);
				free(iboot_in.buf);
				return -1;
			}
		}
        
		if(env_boot_args) {
			ret = patch_env_boot_args(&iboot_in);
			if(!ret) {
				printf("%s: Error doing patch_env_boot_args()!\n", __FUNCTION__);
				free(iboot_in.buf);
				return 0;
			}
		}

		/* Only bootloaders with the kernel load routines pass the DeviceTree. */
        
        if (debug_patch) {
            ret = patch_debug_enabled(&iboot_in);
            if(!ret) {
                printf("%s: Error doing patch_debug_enabled()!\n", __FUNCTION__);
                free(iboot_in.buf);
                return -1;
            }
        }
        
        if(kaslr_patch) {
            ret = disable_kaslr(&iboot_in);
            if(!ret) {
                printf("%s: Error doing disable_kaslr()!\n", __FUNCTION__);
                free(iboot_in.buf);
                return -1;
            }
        }
        
        if(custom_color) {
            ret = patch_bgcolor(&iboot_in, custom_color);
            if(!ret) {
                printf("%s: Error doing patch_bgcolor()!\n", __FUNCTION__);
                free(iboot_in.buf);
                return -1;
            }
        }
        
        if (remote_patch) {
            ret = patch_boot_mode(&iboot_in, 1);
            if(!ret) {
                printf("%s: Error doing patch_boot_mode()!\n", __FUNCTION__);
                free(iboot_in.buf);
                return -1;
            }
            
        }
        
        if (local_patch) {
            ret = patch_boot_mode(&iboot_in, 0);
            if(!ret) {
                printf("%s: Error doing patch_boot_mode()!\n", __FUNCTION__);
                free(iboot_in.buf);
                return -1;
            }
        }
	}

    if (logo_patch) {
        ret = patch_logo(&iboot_in);
        if(!ret) {
            printf("%s: Error doing patch_logo()!\n", __FUNCTION__);
            free(iboot_in.buf);
            return -1;
        }
    }
    
    if (logo4_patch) {
        ret = patch_logo4(&iboot_in);
        if(!ret) {
            printf("%s: Error doing patch_435()!\n", __FUNCTION__);
            free(iboot_in.buf);
            return -1;
        }
    }
    
    if (i433_patch) {
        ret = patch_433orlower_jumpiBoot(&iboot_in);
        if(!ret) {
            printf("%s: Error doing patch_jumptoiBoot()!\n", __FUNCTION__);
            free(iboot_in.buf);
            return -1;
        }
    }
    
    if (ticket_patch) {
        ret = patch_ticket_check(&iboot_in);
        if(!ret) {
            printf("%s: Error doing patch_ticket_check()!\n", __FUNCTION__);
            free(iboot_in.buf);
            return -1;
        }
    }
    
	/* Ensure that the loader has a shell. */
	if(has_recovery_console(&iboot_in) && cmd_handler_str) {
		ret = patch_cmd_handler(&iboot_in, cmd_handler_str, cmd_handler_ptr);
		if(!ret) {
			printf("%s: Error doing patch_cmd_handler()!\n", __FUNCTION__);
			free(iboot_in.buf);
			return -1;
		}
	}

	/* All loaders have the RSA check. */
    
    if (rsa_patch) {
        ret = patch_rsa_check(&iboot_in);
        if(!ret) {
            printf("%s: Error doing patch_rsa_check()!\n", __FUNCTION__);
            free(iboot_in.buf);
            return -1;
        }
    }

    if(boot_partition_patch) {
    	ret = patch_boot_partition(&iboot_in, boot_partition_9);
        if(!ret) {
            printf("%s: Error doing patch_boot_partition()!\n", __FUNCTION__);
            free(iboot_in.buf);
            return -1;
        }
    }
    
    if(boot_ramdisk_patch) {
        ret = patch_boot_ramdisk(&iboot_in);
        if(!ret) {
            printf("%s: Error doing patch_boot_ramdisk()!\n", __FUNCTION__);
            free(iboot_in.buf);
            return -1;
        }
    }
    
    if(setenv_patch) {
    	ret = patch_setenv_cmd(&iboot_in);
    	if(!ret) {
            printf("%s: Error doing patch_setenv_cmd()!\n", __FUNCTION__);
            free(iboot_in.buf);
            return -1;
        }
    }

    memcpy(ibot, iboot_in.buf, len);
	free(iboot_in.buf);

	printf("%s: Quitting...\n", __FUNCTION__);
	return 1;
}
	
