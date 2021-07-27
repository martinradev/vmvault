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

#ifndef MINI_SVM_DEBUG_H
#define MINI_SVM_DEBUG_H

void sevault_log_msg(const char *format, ...);

void sevault_mini_dump_vmcb(struct sevault_mini_vmcb *vmcb);

void sevault_mini_run_tests(struct sevault_mini_context *ctx);

void dump_regs(const struct sevault_mini_vm_state *state);

#endif // MINI_SVM_DEBUG_H
