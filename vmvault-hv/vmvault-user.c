// Copyright (C) 2021 Martin Radev
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "vmvault-user.h"
#include "vmvault.h"
#include "vmvault-user-ioctl.h"
#include "vmvault-debug.h"

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/mm.h>

#include <asm/io.h>

static int vmvault_user_open(struct inode *node, struct file *f) {
	return 0;
}

static int vmvault_user_release(struct inode *node, struct file *f) {
	return 0;
}

static long vmvault_user_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	return -EINVAL;
}

static const struct file_operations vmvault_user_ops = {
	.owner          = THIS_MODULE,
	.release        = vmvault_user_release,
	.open           = vmvault_user_open,
	.unlocked_ioctl = vmvault_user_ioctl,
};

static struct miscdevice vmvault_user_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vmvault_user",
	.fops = &vmvault_user_ops,
};

int vmvault_register_user_node(void) {
	int r;

	r = misc_register(&vmvault_user_misc);
	if (r) {
		return r;
	}

	return 0;
}

void vmvault_deregister_user_node(void) {
	misc_deregister(&vmvault_user_misc);
}
