// SPDX-License-Identifier: GPL-2.0
/*
 * atebeagle_kint - expõe, somente leitura, os ponteiros da sys_call_table em
 * /proc/atebeagle_kint (modo 0400). O agente em userspace calcula o SHA-256 e
 * compara com a referência capturada no boot. Uma sobrescrita de entrada da
 * tabela (técnica clássica de rootkit LKM) muda o hash.
 *
 * Desde o kernel 5.7 kallsyms_lookup_name não é exportado; usamos um kprobe
 * nele apenas para descobrir o endereço (técnica de leitura, nada é alterado).
 *
 * Compilar na placa:  bash kernel/build.sh && sudo insmod kernel/atebeagle_kint.ko
 * Limitação: o módulo roda no mesmo kernel que observa. Um atacante com ring 0
 * pode falsificar esta saída; resistir a isso exige a raiz de confiança em
 * hardware (L1), ausente no AM335x GP. Ver docs/ANALISE_L1.md.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <asm/unistd.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ATEBEAGLE - UNIFOR");
MODULE_DESCRIPTION("Leitura da sys_call_table para atestacao L3.1");

#ifndef __NR_syscalls
#define __NR_syscalls 450
#endif

typedef unsigned long (*lookup_fn)(const char *name);
static unsigned long *table;

static unsigned long resolve(const char *name)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	lookup_fn fn;
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;
	fn = (lookup_fn)kp.addr;
	unregister_kprobe(&kp);
	if (!fn)
		return 0;
	addr = fn(name);
	return addr;
}

static int kint_show(struct seq_file *m, void *v)
{
	int i;

	seq_printf(m, "nr=%d table=%px\n", __NR_syscalls, table);
	for (i = 0; i < __NR_syscalls; i++)
		seq_printf(m, "%d %px\n", i, (void *)table[i]);
	return 0;
}

static int kint_open(struct inode *inode, struct file *file)
{
	return single_open(file, kint_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops kint_fops = {
	.proc_open = kint_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#else
static const struct file_operations kint_fops = {
	.owner = THIS_MODULE,
	.open = kint_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

static int __init kint_init(void)
{
	table = (unsigned long *)resolve("sys_call_table");
	if (!table) {
		pr_err("atebeagle_kint: sys_call_table nao encontrada\n");
		return -ENOENT;
	}
	if (!proc_create("atebeagle_kint", 0400, NULL, &kint_fops))
		return -ENOMEM;
	pr_info("atebeagle_kint: carregado, tabela em %px\n", table);
	return 0;
}

static void __exit kint_exit(void)
{
	remove_proc_entry("atebeagle_kint", NULL);
}

module_init(kint_init);
module_exit(kint_exit);
