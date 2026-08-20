# Kế hoạch 1 tháng: Khép lỗ hổng Disk Forensics + ra sản phẩm portfolio

> **Mục tiêu thực tế của tháng này:** KHÔNG phải "chuyên sâu DFIR" (đó là chuyện 2–3 năm). Mục tiêu hẹp và dùng được: **làm chủ disk forensics ở mức tự tin trả lời phỏng vấn**, và **cho ra một case đi trọn ba nguồn chứng cứ (Event Log / Disk / Memory) kèm anti-forensics** — thứ hiện chưa có trong portfolio.
>
> **Giả định thời gian:** ~20–25h/tuần (≈3h/ngày trong tuần + 5–6h/ngày cuối tuần). Nếu ít hơn: cắt Tuần 2 xuống còn Prefetch + Registry, đẩy phần còn lại sang tháng sau. Đừng nén cả bốn tuần lại.

---

## Vì sao là disk, không phải thứ khác

Toàn bộ portfolio hiện tại là **log forensics** (EVTX/Sysmon) cộng một lần dùng memory để *xác minh* giả thuyết. Không có artifact nào từ ổ đĩa. Trong khi đó:

- CV đang liệt kê Autopsy, FTK Imager, KAPE, Eric Zimmerman Tools ở phần Skills — nhưng phần Projects không có project nào chứng minh mấy tool đó. Interviewer sẽ hỏi vào đúng khoảng trống này.
- Case VSK42 có alert **Important Log File Cleared** (mục 1.6) nhưng chưa được phân tích. Hai alert *Suspicious Service Installation* và *Suspicious Service Name* cũng đang bỏ trống. Khi log bị xóa, chỉ disk artifact cứu được — đó chính là câu trả lời cho phần "chưa đủ khả năng truy nguyên gốc rễ" tự nhận trong báo cáo thực tập.

---

## TUẦN 1 — NTFS và tầng filesystem

**Mục tiêu:** hiểu ổ đĩa *ghi lại* cái gì, độc lập hoàn toàn với Event Log.

### Nội dung
- `$MFT` — resident vs non-resident, MFT entry, attribute
- `$J` (USN Journal), `$LogFile`
- `$I30` — index của thư mục, nơi còn dấu file đã xóa
- Alternate Data Streams (ADS)
- Cụm timestamp **MACB**, đặc biệt cặp `$STANDARD_INFORMATION` vs `$FILE_NAME` (chìa khóa để bắt timestomping)

### Công cụ
`MFTECmd`, `MFTExplorer`, `Timeline Explorer` (Eric Zimmerman).
**Không dùng Autopsy tuần này** — nó giấu mất tầng raw đang cần thấy.

### Tài liệu
- *File System Forensic Analysis* (Brian Carrier) — chương NTFS. Đọc lấy khái niệm, đừng cố nuốt hết, sách rất đặc.
- **13Cubed** (YouTube) — series về NTFS, để có phần hình dung song song với sách.

### ✅ Bài kiểm tra cuối tuần
Trên chính máy lab của bạn:
1. Tạo file → xóa → timestomp một file (SetMace hoặc PowerShell sửa `LastWriteTime`)
2. Parse `$MFT` và tự chứng minh: file nào đã bị xóa, file nào bị timestomp (dấu hiệu: `$SI` lệch với `$FN`)
3. Chỉ ra `$J` đã ghi lại chuỗi thao tác đó ra sao

**Đạt** nếu tự làm được không cần tra cứu.

---

## TUẦN 2 — Execution artifacts, Registry, User activity

**Mục tiêu:** trả lời "chương trình gì đã chạy, lúc nào, ai chạy" khi **không có** Sysmon.

### Execution artifacts
- **Prefetch** — bằng chứng execution mạnh nhất. ⚠️ Tắt mặc định trên Windows Server (nhớ điều này khi làm case server như VSK42)
- AmCache
- ShimCache / AppCompatCache
- SRUM
- BAM / DAM

### Registry
- `RECmd` + `Registry Explorer`
- **Transaction log** (`.LOG1` / `.LOG2`) — hive "dirty" phải replay mới ra dữ liệu mới nhất. Chỗ rất nhiều người bỏ sót và ra kết luận sai.

### User activity
- LNK, Jumplist, Shellbags
- Recycle Bin (`$I` / `$R`)
- ActivityCache

### 🎯 Khái niệm quan trọng nhất tuần này
Với **mỗi** artifact, viết ra hai cột:

| Artifact | Chứng minh được gì | KHÔNG chứng minh được gì |
|----------|--------------------|--------------------------|
| ShimCache | file *tồn tại* trên hệ thống | file *đã chạy* ← sai lầm phổ biến |
| Prefetch | file đã execute, số lần, lần cuối | ai chạy, chạy với quyền gì |
| ... | ... | ... |

Đây đúng là loại lập luận mentor đang chấm ("chỗ nào là bằng chứng, chỗ nào là suy đoán"), chỉ là áp lên tầng disk.

### Tài liệu
- *Windows Forensic Analysis* + *Windows Registry Forensics* (Harlan Carvey) — tra theo artifact, không đọc tuần tự.

### ✅ Bài kiểm tra cuối tuần
Làm 1 disk image từ **Ali Hadi's DFIR challenges** (ashemery.com) — disk image thật, khác hẳn dạng log lab của CyberDefenders.

### 🔧 RE — đúng một cuối tuần, không hơn (5–6 tiếng)
Mở **dnSpyEx** với chính file payload đã dump ra từ `0x400000` (Mono/.NET assembly, 3 sections). Vì là .NET nên đọc được source C# gần như nguyên bản — không cần biết một dòng assembly nào.

Tìm trong đó:
- Config C2 (domain thật, không phải `192.0.2.123` do FakeNet trả lời)
- Thuật toán obfuscate chuỗi
- **Hook keylogger** ← đóng lại mục 2.6 báo cáo njRAT (chỗ phải ghi "T1056.001 chưa quan sát trực tiếp"). Chuyển từ *suy luận* sang *đã kiểm chứng ở tầng code*.

Assembly, IDA/Ghidra, unpacking native → để sau tháng này.

---

## TUẦN 3 — Acquisition, Super Timeline, và dựng case

### Nửa đầu tuần — kỹ thuật
- **KAPE** — targeted collection. Đã quen CDIR-Collector rồi nên học nhanh; KAPE là chuẩn thị trường.
- **Super timeline** — `MFTECmd` + `EvtxECmd` + `PECmd` → `Timeline Explorer`. Biết thêm plaso/psort nhưng dùng EZ Tools làm chính vì nhanh hơn nhiều.
- **DuckDB** trên CSV đã parse — nửa buổi là xong. Giải quyết đúng cái "tốc độ xử lý dữ liệu lớn" tự nhận yếu. Query 1 triệu dòng chạy dưới 1 giây. (Đã có Python sẵn nên tiếp thu nhanh.)

### Nửa sau tuần — dựng case cho capstone
Chạy lại **đúng 4 kỹ thuật ATT&CK cũ** trên lab (T1059.003, T1087.001, T1003.001, T1547.001). Nhưng lần này thêm bước **anti-forensics**:
- Xóa Security log sau khi tấn công
- (khó hơn, tùy chọn) timestomp payload, xóa Prefetch

Rồi thu **full disk image + memory image**.

📌 Ghi lại **ground truth** ra một file riêng — cần nó để tuần sau tự chấm.

---

## TUẦN 4 — Điều tra mù + Memory chủ động + Viết báo cáo

> Tuần quan trọng nhất. Điều tra case tuần 3 **chỉ bằng disk + RAM**, giả vờ như không biết mình đã làm gì.

### 2 ngày đầu — Memory (đảo vai trò của Volatility)
Lần này KHÔNG phải xác minh giả thuyết có sẵn từ Procmon, mà **tự tìm ra bất thường** từ một image không biết trước:
- Cross-view `pslist` vs `psscan` — bắt process bị unlink
- `netscan`
- `cmdline`
- `ldrmodules` — DLL bị unlink
- `hivelist` / `printkey` — registry sống trong RAM, còn giá trị mà hive trên đĩa chưa flush

### Phần thú vị nhất của case: dấu vết của việc xóa log
Khi Security log bị xóa, việc xóa đó vẫn để lại dấu:
- **Event ID 1102** — bản ghi đầu tiên ngay sau khi clear
- **Event ID 104** trong System log
- `$J` ghi lại thao tác trên file `.evtx`
- Bản thân file `.evtx` vẫn có thể còn record trong vùng chưa cấp phát để recover

Tự dựng lại toàn bộ kill chain từ những mảnh này.

### 🏆 Deliverable cuối cùng — Artifact Coverage Matrix
Một bảng: cột là 4 kỹ thuật ATT&CK, hàng là ba nguồn, ô ghi artifact cụ thể nào bắt được kỹ thuật đó.

| Kỹ thuật | Event Log | Disk | Memory |
|----------|-----------|------|--------|
| T1059.003 (Command Interpreter) | Sysmon EID 1 | Prefetch, AmCache | `cmdline`, `psscan` |
| T1087.001 (Account Discovery) | Sysmon EID 1 | Prefetch | ... |
| T1003.001 (LSASS Dumping) | Sysmon EID 1+11 | `$MFT` (file .dmp), Prefetch | `malfind`, handles vào lsass |
| T1547.001 (Run Key) | Sysmon EID 13 | Registry hive + transaction log | `printkey` |

Đối chiếu với ground truth: cái gì tìm ra, cái gì bỏ sót, **cái gì sống sót sau khi log bị xóa**.

👉 Bảng này đi thẳng vào đồ án được — nó là phần "tại sao cần multi-source evidence" mà hội đồng luôn hỏi, nhưng có **số liệu tự đo** chứ không phải trích sách. Cũng chính là câu trả lời trực tiếp cho alert *Important Log File Cleared* mà case VSK42 để trống.

---

## Danh sách KHÔNG làm trong tháng này

Quan trọng ngang phần nội dung chính:

- ❌ Không thêm lab CyberDefenders — đã thạo dạng đó, thêm nữa là học lại cái đã biết
- ❌ Không Linux / macOS / mobile forensics
- ❌ Không network forensics chuyên sâu (PCAP, Zeek)
- ❌ Không x86 assembly
- ❌ Không cloud forensics (dù đang hot)

---

## Sau 1 tháng bạn ở đâu

Không phải "chuyên sâu DFIR". Nhưng:

- Làm chủ disk artifacts ở mức tự tin trả lời phỏng vấn
- Có một case đi trọn **ba nguồn chứng cứ** với anti-forensics
- Có **Artifact Coverage Matrix** để đưa vào đồ án
- Một mục GitHub khác hẳn ba repo hiện có
- CV không còn khoảng trống giữa phần Skills (KAPE, Autopsy, FTK Imager) và phần Projects

Đủ để lên **Phase 2 của HPT** không bị hụt (endpoint compromise + điều tra bộ nhớ chuyên sâu + tương quan log đa nguồn).

---

## Tài liệu tổng hợp (tham chiếu nhanh)

**Sách**
- *File System Forensic Analysis* — Brian Carrier (nền tảng NTFS)
- *The Art of Memory Forensics* (kinh thánh RAM; viết theo Vol 2, cần tự map plugin sang v3)
- *Windows Forensic Analysis* + *Windows Registry Forensics* — Harlan Carvey (disk/registry thực chiến)
- *Windows Internals Part 1* — Russinovich (đọc rải, tầng nền dưới cả memory forensics lẫn RE)

**Video / miễn phí**
- **13Cubed** (Richard Davis) — chất lượng ngang khóa trả tiền; series "Investigating Windows Endpoints" là thứ gần nhất với "lý thuyết disk bài bản"
- **OALabs**, **MalwareUnicorn RE101/RE102** — cho phần RE

**Lab có disk image thật**
- Ali Hadi's DFIR challenges — ashemery.com
- Magnet CTF archives
