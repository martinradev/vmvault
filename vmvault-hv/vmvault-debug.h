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

#ifndef VMVAULT_DEBUG_H
#define VMVAULT_DEBUG_H

void vmvault_log_msg(const char *format, ...);

void vmvault_dump_vmcb(struct vmvault_vmcb *vmcb);

void vmvault_run_tests(struct vmvault_context *ctx);

void vmvault_dump_regs(const struct vmvault_vm_state *state);

#endif // VMVAULT_DEBUG_H
