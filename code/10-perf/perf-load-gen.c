/* perf-load-gen.c — 第十篇：受控 openat 负载生成器
 * 编译: gcc -O2 -o perf-load-gen perf-load-gen.c
 * 用法: ./perf-load-gen <文件数> <重复次数>
 *   每个进程遍历 N 个文件，重复 R 次，产生 N*R 次 openat 调用
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <time.h>

#define MAX_FILES 10000
#define MAX_PATH 512

static char *file_list[MAX_FILES];
static int file_count = 0;

/* 递归扫描目录，收集文件路径 */
void scan_dir(const char *dir, int max_depth) {
    if (file_count >= MAX_FILES || max_depth <= 0) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *entry;
    char path[MAX_PATH];
    while ((entry = readdir(d)) && file_count < MAX_FILES) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
        if (entry->d_type == DT_REG) {
            file_list[file_count] = strdup(path);
            file_count++;
        } else if (entry->d_type == DT_DIR) {
            scan_dir(path, max_depth - 1);
        }
    }
    closedir(d);
}

int main(int argc, char *argv[]) {
    int n_files = (argc > 1) ? atoi(argv[1]) : 1000;
    int n_loops = (argc > 2) ? atoi(argv[2]) : 5;
    const char *scan_path = (argc > 3) ? argv[3] : "/usr/lib";

    /* 收集文件列表 */
    fprintf(stderr, "[LoadGen] 扫描 %s ...\n", scan_path);
    scan_dir(scan_path, 3);
    fprintf(stderr, "[LoadGen] 找到 %d 个文件, 循环 %d 次\n", file_count, n_loops);

    if (file_count == 0) {
        fprintf(stderr, "[LoadGen] 没有文件可打开, 退出\n");
        return 1;
    }

    /* 受控循环：只 open/close，不读写 */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    long total_ops = 0;
    int actual = (n_files < file_count) ? n_files : file_count;

    for (int loop = 0; loop < n_loops; loop++) {
        for (int i = 0; i < actual; i++) {
            int fd = open(file_list[i], O_RDONLY);
            if (fd >= 0) {
                close(fd);
                total_ops++;
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    fprintf(stderr, "[LoadGen] 完成: %ld 次 openat 在 %.2f 秒, 速率 %.0f/s\n",
            total_ops, elapsed, total_ops / elapsed);
    return 0;
}
