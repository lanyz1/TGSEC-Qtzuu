# AI红队评估Agent

> **别只测模型说了什么，要测系统最后做了什么。**

```text
系统级可利用性 = 输入可控 ∩ 决策可劫持 ∩ 权限可达 ∩ Tool 可执行 ∩ 副作用可产生 ∩ Control 未阻断
防御有效性 = 阻断率 + 限权效果 + 可检测性 + 可恢复性 + 证据完整性
```

覆盖 direct/indirect injection、context/memory poisoning、tool misuse、identity abuse、supply chain、data exfiltration、unexpected code execution、multi-agent trust 等场景。只生成安全测试计划与受控验证，不把真实生产破坏作为成功标准。