/*
*	Interactive disassembler (IDA).
*	Copyright (c) 1990-2022 by Ilfak Guilfanov, <ig@datarescue.com>
*	ALL RIGHTS RESERVED.
*/

#define VERSION "1.1"
/*
*	SEGA DREAMCAST RAM Loader for IDA 7.x
*	Author: Dr. MefistO [Lab 313] <meffi@lab313.ru>
*	Contribution: pr701
*/

#include <cstdint>
#include <string>

#include <ida.hpp>
#include <idp.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>

#ifndef MAX_FILE_FORMAT_NAME
#define MAX_FILE_FORMAT_NAME	64
#endif

idaman loader_t ida_module_data LDSC;

ea_t rams[] = { 0x8C000000, 0x0C000000, 0 };

#define countof(x)	(sizeof(x) / sizeof(x[0]))
#define rams_count	countof(rams)

struct ram_chooser_t : public chooser_t
{
protected:
	static const int widths_[];
	static const char* const header_[];

public:
	ram_chooser_t() : chooser_t(CH_MODAL | CH_NOIDB, 1, widths_, header_, "Select Loading Address")
	{}

	// function that returns number of lines in the list
	size_t idaapi get_count() const override
	{
		return rams_count;
	}

	// function that generates the list line
	void idaapi get_row(
		qstrvec_t* cols,
		int* icon_,
		chooser_item_attrs_t* attrs,
		size_t n) const override
	{
		qstrvec_t& _cols = *cols;
		char buffer[32];
		qsnprintf(buffer, 32, "0x%08.8x", rams[n]);
		_cols[0] = buffer;
	}

	cbret_t idaapi enter(size_t n) override
	{
		return cbret_t();
	}
};
const int ram_chooser_t::widths_[] =
{
  32, // RAM Address
};
const char* const ram_chooser_t::header_[] =
{
  "RAM Address", // 0
};

//--------------------------------------------------------------------------
static void print_version()
{
	static const char format[] = "SEGA DREAMCAST RAM loader plugin v%s;\n"
		"Author: Dr.MefistO[Lab 313] <meffi@lab313.ru>.\n"
		"Contribution: pr701";
	info(format, VERSION);
	msg(format, VERSION);
}

//--------------------------------------------------------------------------
int idaapi accept_file(
	qstring* fileformatname,
	qstring* processor,
	linput_t* li,
	const char* filename)
{
    int size = qlsize(li);
    if (size != 16 * 1024 * 1024 && size != 32 * 1024 * 1024)
        return 0;

	*fileformatname = "SEGA DREAMCAST RAM";
	*processor = "SH4";
	return 1;
}

static void add_segment(ea_t start, ea_t end, const char *name, const char *class_name, const char *cmnt)
{
    if (!add_segm(0, start, end, name, class_name)) loader_failure();
    segment_t *segm = getseg(start);
    set_segment_cmt(segm, cmnt, false);
	create_byte(start, 1);
}

//--------------------------------------------------------------------------
static qstring device = "SH7750";
static ioports_t ports;
static const char cfgname[] = "sh3.cfg";

static void load_symbols(void)
{
	ports.clear();
	read_ioports(&ports, &device, cfgname);
}

static void apply_symbols(void)
{
    std::string name;
    for (size_t i = 0; i < ports.size(); ++i)
    {
        name.assign(ports[i].name.c_str());
        size_t tail_pos = name.length() - 2;
        std::string tail = name.substr(tail_pos);

        if (tail[0] == '_')
        {
            if (tail == "_L")
				create_dword(ports[i].address, 4);
            else if (tail == "_W")
				create_word(ports[i].address, 2);
            else if (tail == "_B")
				create_byte(ports[i].address, 1);

            name = name.substr(0, tail_pos);
        }
        else if (tail == "WB") // "_WB"
        {
			create_word(ports[i].address, 2);
            name = name.substr(0, tail_pos);
        }
        else
			create_dword(ports[i].address, 4);

        set_name(ports[i].address, name.c_str(), SN_NOWARN);
        set_cmt(ports[i].address, ports[i].cmt.c_str(), false);
    }
}

//--------------------------------------------------------------------------

enum EVariableSize
{
	EByte = 0,
	EWord,
	EDword,
};

void add_name(ea_t address, int var_type, const char* name, const char* comment)
{
	switch (var_type)
	{
	case EByte:
		create_byte(address, 1);
		break;
	case EWord:
		create_word(address, 2);
		break;
	case EDword:
		create_dword(address, 4);
		break;
	default:
		break;
	}
	if (name) set_name(address, name, SN_PUBLIC | SN_AUTO | SN_NOWARN);
	if (comment) set_cmt(address, comment, false);
}

void add_ccn_segment()
{
	add_segment(0xFF000000, 0xFF000048, "CCN", "DATA", NULL);
	add_name(0xFF000000, EDword, "CCN_PTEH", "Page table entry high register");
	add_name(0xFF000004, EDword, "CCN_PTEL", "Page table entry low register");
	add_name(0xFF000008, EDword, "CCN_TTB", "Translation table base register");
	add_name(0xFF00000C, EDword, "CCN_TEA", "TLB exception address register");
	add_name(0xFF000010, EDword, "CCN_MMUCR", "MMU control register");
	add_name(0xFF000014, EByte, "CCN_BASRA", "Break ASID register A");
	add_name(0xFF000018, EByte, "CCN_BASRB", "Break ASID register B");
	add_name(0xFF00001C, EDword, "CCN_CCR", "Cache control register");
	add_name(0xFF000020, EDword, "CCN_TRA", "TRAPA exception register");
	add_name(0xFF000024, EDword, "CCN_EXPEVT", "Exception event register");
	add_name(0xFF000028, EDword, "CCN_INTEVT", "Interrupt event register");
	add_name(0xFF000030, EDword, "CCN_PVR", "Processor version register");
	add_name(0xFF000034, EDword, "CCN_PTEA", "Page table entry assistance register");
	add_name(0xFF000038, EDword, "CCN_QACR0", "Queue address control register 0");
	add_name(0xFF00003C, EDword, "CCN_QACR1", "Queue address control register 1");
	add_name(0xFF000044, EDword, "CCN_PRR", "Product register");
}

void add_ubc_segment()
{
	add_segment(0xFF200000, 0xFF200024, "UBC", "DATA", NULL);
	add_name(0xFF200000, EDword, "UBC_BARA", "Break address register A");
	add_name(0xFF200004, EByte, "UBC_BAMRA", "Break address mask register A");
	add_name(0xFF200008, EWord, "UBC_BBRA", "Break bus cycle register A");
	add_name(0xFF20000C, EDword, "UBC_BARB", "Break address register B");
	add_name(0xFF200010, EByte, "UBC_BAMRB", "Break address mask register B");
	add_name(0xFF200014, EWord, "UBC_BBRB", "Break bus cycle register B");
	add_name(0xFF200018, EDword, "UBC_BDRB", "Break data register B");
	add_name(0xFF20001C, EDword, "UBC_BDMRB", "Break data mask register B");
	add_name(0xFF200020, EWord, "UBC_BRCR", "Break control register");
}

void add_bsc_segment()
{
	add_segment(0xFF800000, 0xFF80004C, "BSC", "DATA", NULL);
	add_name(0xFF800000, EDword, "BSC_BCR1", "Bus control register 1");
	add_name(0xFF800004, EWord, "BSC_BCR2", "Bus control register 2");
	add_name(0xFF800008, EDword, "BSC_WCR1", "Wait state control register 1");
	add_name(0xFF80000C, EDword, "BSC_WCR2", "Wait state control register 2");
	add_name(0xFF800010, EDword, "BSC_WCR3", "Wait state control register 3");
	add_name(0xFF800014, EDword, "BSC_MCR", "Memory control register");
	add_name(0xFF800018, EWord, "BSC_PCR", "PCMCIA control register");
	add_name(0xFF80001C, EWord, "BSC_RTCSR", "Refresh timer control/status register");
	add_name(0xFF800020, EWord, "BSC_RTCNT", "Refresh timer counter");
	add_name(0xFF800024, EWord, "BSC_RTCOR", "Refresh time constant counter");
	add_name(0xFF800028, EWord, "BSC_RFCR", "Refresh count register");
	add_name(0xFF80002C, EDword, "BSC_PCTRA", "Port control register A");
	add_name(0xFF800030, EWord, "BSC_PDTRA", "Port data register A");
	add_name(0xFF800040, EDword, "BSC_PCTRB", "Port control register B");
	add_name(0xFF800044, EWord, "BSC_PDTRB", "Port data register B");
	add_name(0xFF800048, EWord, "BSC_GPIOC", "GPIO interrupt control register");

	add_segment(0xFF900000, 0xFF910000, "BSC_SDMR2", "BSS", NULL);
	add_name(0xFF900000, EDword, "BSC_SDMR2", "Synchronous DRAM mode registers for area 2");

	add_segment(0xFF940000, 0xFF950000, "BSC_SDMR3", "BSS", NULL);
	add_name(0xFF940000, EDword, "BSC_SDMR3", "Synchronous DRAM mode registers for area 3");
}

void add_dmac_segment()
{
	add_segment(0xFFA00000, 0xFFA00044, "DMAC", "DATA", NULL);
	add_name(0xFFA00000, EDword, "DMAC_SAR0", "DMA source address register 0");
	add_name(0xFFA00004, EDword, "DMAC_DAR0", "DMA destination address register 0");
	add_name(0xFFA00008, EDword, "DMAC_DMATCR0", "DMA transfer count register 0");
	add_name(0xFFA0000C, EDword, "DMAC_CHCR0", "DMA channel control register 0");
	add_name(0xFFA00010, EDword, "DMAC_SAR1", "DMA source address register 1");
	add_name(0xFFA00014, EDword, "DMAC_DAR1", "DMA destination address register 1");
	add_name(0xFFA00018, EDword, "DMAC_DMATCR1", "DMA transfer count register 1");
	add_name(0xFFA0001C, EDword, "DMAC_CHCR1", "DMA channel control register 1");
	add_name(0xFFA00020, EDword, "DMAC_SAR2", "DMA source address register 2");
	add_name(0xFFA00024, EDword, "DMAC_DAR2", "DMA destination address register 2");
	add_name(0xFFA00028, EDword, "DMAC_DMATCR2", "DMA transfer count register 2");
	add_name(0xFFA0002C, EDword, "DMAC_CHCR2", "DMA channel control register 2");
	add_name(0xFFA00030, EDword, "DMAC_SAR3", "DMA source address register 3");
	add_name(0xFFA00034, EDword, "DMAC_DAR3", "DMA destination address register 3");
	add_name(0xFFA00038, EDword, "DMAC_DMATCR3", "DMA transfer count register 3");
	add_name(0xFFA0003C, EDword, "DMAC_CHCR3", "DMA channel control register 3");
	add_name(0xFFA00040, EDword, "DMAC_DMAOR", "DMA operation register");
}

void add_cpg_segment()
{
	add_segment(0xFFC00000, 0xFFC00014, "CPG", "DATA", NULL);
	add_name(0xFFC00000, EWord, "CPG_FRQCR", "Frequency control register");
	add_name(0xFFC00004, EByte, "CPG_STBCR", "Standby control register");
	add_name(0xFFC00008, EWord, "CPG_WTCNT", "Watchdog timer counter");
	add_name(0xFFC0000C, EWord, "CPG_WTCSR", "Watchdog timer control/status register");
	add_name(0xFFC00010, EByte, "CPG_STBCR2", "Standby control register 2");
}

void add_rtc_segment()
{
	add_segment(0xFFC80000, 0xFFC80040, "RTC", "DATA", NULL);
	add_name(0xFFC80000, EByte, "RTC_R64CNT", "64 Hz counter");
	add_name(0xFFC80004, EByte, "RTC_RSECCNT", "Second counter");
	add_name(0xFFC80008, EByte, "RTC_RMINCNT", "Minute counter");
	add_name(0xFFC8000C, EByte, "RTC_RHRCNT", "Hour counter");
	add_name(0xFFC80010, EByte, "RTC_RWKCNT", "Day-of-week counter");
	add_name(0xFFC80014, EByte, "RTC_RDAYCNT", "Day counter");
	add_name(0xFFC80018, EByte, "RTC_RMONCNT", "Month counter");
	add_name(0xFFC8001C, EWord, "RTC_RYRCNT", "Year counter");
	add_name(0xFFC80020, EByte, "RTC_RSECAR", "Second alarm register");
	add_name(0xFFC80024, EByte, "RTC_RMINAR", "Minute alarm register");
	add_name(0xFFC80028, EByte, "RTC_RHRAR", "Hour alarm register");
	add_name(0xFFC8002C, EByte, "RTC_RWKAR", "Day-of-week alarm register");
	add_name(0xFFC80030, EByte, "RTC_RDAYAR", "Day alarm register");
	add_name(0xFFC80034, EByte, "RTC_RMONAR", "Month alarm register");
	add_name(0xFFC80038, EByte, "RTC_RCR1", "RTC control register 1");
	add_name(0xFFC8003C, EByte, "RTC_RCR2", "RTC control register 2");
}

void add_intc_segment()
{
	add_segment(0xFFD00000, 0xFFD00010, "INTC", "DATA", NULL);
	add_name(0xFFD00000, EWord, "INTC_ICR", "Interrupt control register");
	add_name(0xFFD00004, EWord, "INTC_IPRA", "Interrupt priority register A");
	add_name(0xFFD00008, EWord, "INTC_IPRB", "Interrupt priority register B");
	add_name(0xFFD0000C, EWord, "INTC_IPRC", "Interrupt priority register C");
}

void add_tmu_segment()
{
	add_segment(0xFFD80000, 0xFFD80030, "TMU", "DATA", NULL);
	add_name(0xFFD80000, EByte, "TMU_TOCR", "Timer output control register");
	add_name(0xFFD80004, EByte, "TMU_TSTR", "Timer start register");
	add_name(0xFFD80008, EDword, "TMU_TCOR0", "Timer constant register 0");
	add_name(0xFFD8000C, EDword, "TMU_TCNT0", "Timer counter 0");
	add_name(0xFFD80010, EWord, "TMU_TCR0", "Timer control register 0");
	add_name(0xFFD80014, EDword, "TMU_TCOR1", "Timer constant register 1");
	add_name(0xFFD80018, EDword, "TMU_TCNT1", "Timer counter 1");
	add_name(0xFFD8001C, EWord, "TMU_TCR1", "Timer control register 1");
	add_name(0xFFD80020, EDword, "TMU_TCOR2", "Timer constant register 2");
	add_name(0xFFD80024, EDword, "TMU_TCNT2", "Timer counter 2");
	add_name(0xFFD80028, EWord, "TMU_TCR2", "Timer control register 2");
	add_name(0xFFD8002C, EDword, "TMU_TCPR2", "Input capture register");
}

void add_sci_segment() 
{
	add_segment(0xFFE00000, 0xFFE00020, "SCI", "DATA", NULL);
	add_name(0xFFE00000, EByte, "SCI_SCSMR1", "Serial mode register");
	add_name(0xFFE00004, EByte, "SCI_SCBRR1", "Bit rate register");
	add_name(0xFFE00008, EByte, "SCI_SCSCR1", "Serial control register");
	add_name(0xFFE0000C, EByte, "SCI_SCTDR1", "Transmit data register");
	add_name(0xFFE00010, EByte, "SCI_SCSSR1", "Serial status register");
	add_name(0xFFE00014, EByte, "SCI_SCRDR1", "Receive data register");
	add_name(0xFFE00018, EByte, "SCI_SCSCMR1", "Smart card mode register");
	add_name(0xFFE0001C, EByte, "SCI_SCSPTR1", "Serial port register");
}

void add_scif_segment()
{
	add_segment(0xFFE80000, 0xFFE80028, "SCIF", "DATA", NULL);
	add_name(0xFFE80000, EWord, "SCIF_SCSMR2", "Serial mode register");
	add_name(0xFFE80004, EByte, "SCIF_SCBRR2", "Bit rate register");
	add_name(0xFFE80008, EWord, "SCIF_SCSCR2", "Serial control register");
	add_name(0xFFE8000C, EByte, "SCIF_SCFTDR2", "Transmit FIFO data register");
	add_name(0xFFE80010, EWord, "SCIF_SCFSR2", "Serial status register");
	add_name(0xFFE80014, EByte, "SCIF_SCFRDR2", "Receive FIFO data register");
	add_name(0xFFE80018, EWord, "SCIF_SCFCR2", "FIFO control register");
	add_name(0xFFE8001C, EWord, "SCIF_SCFDR2", "FIFO data count register");
	add_name(0xFFE80020, EWord, "SCIF_SCSPTR2", "Serial port register");
	add_name(0xFFE80024, EWord, "SCIF_SCLSR2", "Line status register");
}

void add_hudi_segment()
{
	add_segment(0xFFF00000, 0xFFF0000C, "HUDI", "DATA", NULL);
	add_name(0xFFF00000, EWord, "HUDI_SDIR", "Instruction register");
	add_name(0xFFF00008, EDword, "HUDI_SDDR", "Data register");
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort neflags, const char *fileformatname)
{
    if (ph.id != PLFM_SH) {
		set_processor_type("SH4", SETPROC_LOADER_NON_FATAL); // Motorola 68000
	}

	add_ccn_segment();
	add_ubc_segment();
	add_bsc_segment();
	add_dmac_segment();
	add_cpg_segment();
	add_rtc_segment();
	add_intc_segment();
	add_tmu_segment();
	add_sci_segment();
	add_scif_segment();
	add_hudi_segment();

	unsigned int size = qlsize(li); // size of rom
	qlseek(li, 0, SEEK_SET);

	ram_chooser_t* ch = new ram_chooser_t();
	ssize_t choice = ch->choose();
	if (choice <= chooser_base_t::NO_SELECTION)
	{
		error("Loading was canceled!");
		return;
	}

    bool t = add_segm(0, rams[choice], rams[choice] + 0x02000000, "RAM", "DATA");
    file2base(li, 0, rams[choice], rams[choice] + size, FILEREG_PATCHABLE); // load rom to database

    load_symbols();
    apply_symbols();

	inf.af = 0
		| AF_FIXUP //        0x0001          // Create offsets and segments using fixup info
		| AF_MARKCODE  //     0x0002          // Mark typical code sequences as code
		| AF_UNK //          0x0004          // Delete instructions with no xrefs
		| AF_CODE //         0x0008          // Trace execution flow
		| AF_PROC //         0x0010          // Create functions if call is present
		| AF_USED //         0x0020          // Analyze and create all xrefs
		//| AF_FLIRT //        0x0040          // Use flirt signatures
		| AF_PROCPTR //      0x0080          // Create function if data xref data->code32 exists
		| AF_JFUNC //        0x0100          // Rename jump functions as j_...
		| AF_NULLSUB //      0x0200          // Rename empty functions as nullsub_...
		//| AF_LVAR //         0x0400          // Create stack variables
		//| AF_TRACE //        0x0800          // Trace stack pointer
		| AF_STRLIT //        0x1000          // Create string if data xref exists
		//| AF_IMMOFF //       0x2000          // Convert 32bit instruction operand to offset
		//AF_DREFOFF //      0x4000          // Create offset if data xref to seg32 exists
		| AF_FINAL //       0x8000          // Final pass of analysis
		;
	inf.af2 = 0
		| AF_JUMPTBL  //    0x0001          // Locate and create jump tables
		//| AF2_DODATA  //     0x0002          // Coagulate data segs at the final pass
		//| AF2_HFLIRT  //     0x0004          // Automatically hide library functions
		| AF_STKARG  //     0x0008          // Propagate stack argument information
		| AF_REGARG  //     0x0010          // Propagate register argument information
		//| AF_CHKUNI  //     0x0020          // Check for unicode strings
		//| AF_SIGCMT  //     0x0040          // Append a signature name comment for recognized anonymous library functions
		| AF_SIGMLT  //     0x0080          // Allow recognition of several copies of the same function
		| AF_FTAIL  //      0x0100          // Create function tails
		| AF_DATOFF  //     0x0200          // Automatically convert data to offsets
		//| AF_ANORET  //     0x0400          // Perform 'no-return' analysis
		//| AF_VERSP  //      0x0800          // Perform full SP-analysis (ph.verify_sp)
		//| AF_DOCODE  //     0x1000          // Coagulate code segs at the final pass
		| AF_TRFUNC  //     0x2000          // Truncate functions upon code deletion
		//| AF2_PURDAT  //     0x4000          // Control flow to data segment is ignored
		//| AF2_MEMFUNC //    0x8000          // Try to guess member function types
		;

	print_version();
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
	IDP_INTERFACE_VERSION,
	0,                            // loader flags
	//
	//      check input file format. if recognized, then return 1
	//      and fill 'fileformatname'.
	//      otherwise return 0
	//
	accept_file,
	//
	//      load file into the database.
	//
	load_file,
	//
	//      create output file from the database.
	//      this function may be absent.
	//
	NULL,
	//      take care of a moved segment (fix up relocations, for example)
	NULL
};
