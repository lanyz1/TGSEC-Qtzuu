# vdp-finder — VDP/赏金项目新目标监控

用途: 基于公开赏金目标数据集，监控各大 VDP/Bugcrowd/H1/Intigriti 平台 **新出现**的项目，输出新增目标的 scope。

## 用法
```bash
python3 vdp_finder.py            # 打印新项目
# 首次运行生成 seen_cache.json；之后只报增量
```

## 备注
- 纯 stdlib，无依赖。
- 与本地 recon 流程配合：新目标 → 走现有 recon 流水线；只用于**公开 VDP 范围**的目标发现。
