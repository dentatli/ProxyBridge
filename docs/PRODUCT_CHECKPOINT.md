# Product checkpoint — 2026-10-24

Scope: offline WFP/Core full50 diagnosis; лаборатория развивается в другом чате.
Ветка `codex/wfp-full50-offline-diagnosis` от integration `driver`
`b3596272a8dc8898790b016d1e4c488c2fdc917d`; изменения только docs.
Исходная `codeql-whcp-fixes-ea115fa`137d128 сохранена. PR/merge не разрешены.

Читать сначала [результат и bounded trial](WFP_FULL50_OFFLINE_DIAGNOSIS_2026-10-24.md).

- Preview41/source7e40248 full50 attempt
  `20261024-124933-0f41ea6ddd64496f8206634cbdaf39e1`:36PASS/14FAIL;
  Core b359627 + сохранённый baseline SYS3e5c3c70, не новый SYS из b359.
- P1/P2/P4: baseline UDP map/ownership/return-source причины сверены с кодом.
  8226 valid-HMAC wrong-flow replies — cross-delivery, не физическая потеря.
- P3: сильная новая гипотеза — четыре asyncio socketpair connects на worker
  перехвачены до SSH coroutine. Все8records имеют action=1(DIRECT), cfg0,
  но baseline теряет action и использует proxy. Этот дефект исправлен340bdc8;
  восстановление SSH/SFTP им не измерено. Не считать ephemeral-порты доказанным
  повреждением SSH original destination. Нужны listener tuple + thread stacks.
- Уже имеются отдельные локальные runtime gates UDP b993913/final1.1.0.0
  и TCP DIRECT340bdc8; они не являются новым combined full50.
- Offline review exit0,18 input hashes:
  `C:/src/ProxyBridge-TestLab/artifacts/diagnostics/full50-product-offline-20261024-r1/review.json`.
  Raw `%LOCALAPPDATA%/ProxyBridge-TestLab/traffic-lab/<attempt>` не менялись;
  private captures/scripts не коммитить. Актуальные full50 docs находятся в
  `C:/Users/LabAdmin/.codex/worktrees/testlab-development/ProxyBridge-TestLab/docs/`.
- В этом чате product/driver/WinDbg trials, builds, installs не выполнялись;
  controller/PnP runtime state заново не проверялось, т.к. вмешательства не было.
  Следующий шаг — отдельный допуск к трём socketpair cases: OFF, baseline,
  Core340bdc8 на прежнем SYS, deadline8s/case, без установки/перезагрузки.
  Private `socketpair_probe.py` подготовлен, AST PASS, не запускался;
  product lifecycle/PnP restoration остаются обязанностью внешнего controller.
- Не менять trust/BCD/proxy/power; KernelReadCapture/hiddenkd запрещены.
  WinDbg target только физический PB-SUT192.168.0.157; VM не debuggee.
  Новые kernel packages, combined build/full50 требуют своего scope.
- Последние лимиты: осталось91% primary/54% weekly; перед новым длительным
  этапом перечитать usage. При любом remaining<=5% новое не начинать.
