#include <cstdio>
#include <memory>
#include <vector>
#include <exception>
#include <queue>
#include <cstdlib>
#include <cassert>
#include <csignal>
#include <getopt.h>
#include <string>
#include "verilated.h"
#include "Vcore.h"

#ifdef DEBUG
#define debug(f_, ...) printf((f_), ##__VA_ARGS__)
#else
#define debug(...) do {} while(0)
#endif

uint64_t main_time = 0;
uint32_t halt_addr = 0x00000000;

//const uint32_t uart_txdata_addr = 0x00001000;
const uint32_t uart_txdata_addr_w = 0x10013000;
const uint32_t uart_txdata_addr_r = 0x10013004;

//const uint32_t itmi_addr = 0x08000000;
const uint32_t rom_addr = 0x20000000;
const uint32_t ram_addr = 0x80000000;

double sc_time_stamp() {
    return main_time;
}

class SimulatedRAM {
    std::shared_ptr<Vcore> core;
    std::vector<uint8_t> itmi;
    std::vector<uint8_t> rom;
    std::vector<uint8_t> memory;
    //std::vector<uint8_t> framebuffer;
    size_t capacity;
    uint64_t icache_next_rdy;
    uint64_t dcache_next_rdy;
    int icache_state; // 0 -> reset; 1 -> reading
    int dcache_state; // 0 -> reset; 1 -> reading/writing

    public:
    SimulatedRAM(std::shared_ptr<Vcore> core, 
            size_t itmi_cap,
            size_t rom_cap,
            size_t ram_cap): \
            core(core), capacity(ram_cap),
            icache_next_rdy(0),
            dcache_next_rdy(0) {
        itmi.resize(itmi_cap);
        rom.resize(rom_cap);
        memory.resize(ram_cap);
        core->icache_rdy = 0;
        core->dcache_rdy = 0;
    }

    void load_image_from_file(FILE *img_file, size_t mem_off, size_t len = 0) {
        if (len == 0)
        {
            auto old = ftell(img_file);
            fseek(img_file, 0L, SEEK_END);
            len = ftell(img_file);
            fseek(img_file, old, SEEK_SET);
        }
        fread(&rom[0], 1, len, img_file);
    }

    void eval_posedge() {
        if (core->reset == 1)
        {
            debug("reset ram\n");
            icache_state = 0;
            dcache_state = 0;
            core->icache_rdy = 0;
            core->dcache_rdy = 0;
            return;
        }
        if (icache_state == 0)
        {
            core->icache_rdy = 0;
            if (core->icache_req)
                icache_state = 1;
        }
        if (icache_state == 1)
        {
            if (icache_next_rdy == 0)
            {
                //assert(core->icache_addr + 4 < capacity);
                //auto addr = core->icache_addr - rom_addr;
                auto addr = core->icache_addr - rom_addr;
                core->icache_data = \
                    rom[addr] |
                    (rom[addr + 1] << 8) |
                    (rom[addr + 2] << 16) |
                    (rom[addr + 3] << 24);
                //printf("%x %x %08x\n", core->icache_addr, addr, core->icache_data);
                core->icache_rdy = 1;
                icache_state = 0;
                debug("icache: read byte @ %08x = %08x\n",
                      core->icache_addr, core->icache_data);
                //schedule_next_icache_rdy(4);
            } else icache_next_rdy--;
        }

        if (dcache_state == 0)
        {
            core->dcache_rdy = 0;
            if (core->dcache_req)
                dcache_state = 1;
        }
        if (dcache_state == 1)
        {
            if (dcache_next_rdy == 0)
            {
                auto addr = core->dcache_addr;
                auto data = core->dcache_wdata;
                if (addr == uart_txdata_addr_r)
                {
                    printf("uart read\n");
                    /*
                    if (core->dcache_wr)
                    {
                        debug("dcache: write uart = %02x\n", addr, data);
                        putchar((uint8_t)data);
                    }
                    else
                    {
                        core->dcache_rdata = 0;
                        debug("dcache: read uart = %02x\n", core->dcache_rdata);
                    }
                    */
                    //putchar((uint8_t)data);
                }
                else if (addr == uart_txdata_addr_w) {
                    printf("uart write\n");
                } else {
                    uint8_t *m = &rom[0];
                    if (addr >= rom_addr && addr < rom_addr + rom.capacity()) {
                        m = &rom[0];
                        addr -= rom_addr;
                        assert(!core->dcache_wr);
                        assert(addr < rom.capacity());
                        core->dcache_rdata = *(uint32_t *)(m + addr);
                    } if (addr >= ram_addr && addr < ram_addr + memory.capacity()) {
                        m = &memory[0];
                        addr -= ram_addr;
                        assert(addr < memory.capacity());

                        if (core->dcache_wr)
                        {
                            if (core->dcache_ws == 0)
                            {
                                debug("dcache: write byte @ %08x = %02x\n", addr, data);
                                m[addr] = data & 0xff;
                            }
                            else if (core->dcache_ws == 1)
                            {
                                debug("dcache: write halfword @ %08x = %04x\n", addr, data);
                                m[addr] = data & 0xff;
                                m[addr + 1] = (data >> 8) & 0xff;
                            }
                            else if (core->dcache_ws == 2)
                            {
                                debug("dcache: write word @ %08x = %08x\n", addr, data);
                                m[addr] = data & 0xff;
                                m[addr + 1] = (data >> 8) & 0xff;
                                m[addr + 2] = (data >> 16) & 0xff;
                                m[addr + 3] = (data >> 24) & 0xff;
                            }
                            else assert(0);
                        }
                        else
                        {
                            core->dcache_rdata = *(uint32_t *)(m + addr);
                            debug("dcache: read word @ %08x = %08x\n", addr, core->dcache_rdata);
                        }
                    } 
                }
                core->dcache_rdy = 1;
                dcache_state = 0;
                //schedule_next_dcache_rdy(1);
            } else {
                debug("delayed dcache response: %lu\n", dcache_next_rdy);
                dcache_next_rdy--;
            }
        }
    }

    void schedule_next_icache_rdy(uint64_t nstep) {
        icache_next_rdy = nstep;
    }

    void schedule_next_dcache_rdy(uint64_t nstep) {
        dcache_next_rdy = nstep;
    }

    /*
    uint8_t *get_framebuffer() {
        return &framebuffer[0];
    }
    */

    uint8_t *get_ram() {
        return &memory[0];
    }
};

struct SoC {
    std::shared_ptr<Vcore> core;
    SimulatedRAM ram;

    SoC(std::shared_ptr<Vcore> core, size_t itmi_cap, size_t rom_cap, size_t mem_cap): core(core), ram(core, itmi_cap, rom_cap, mem_cap) {}

    void reset() {
        core->clock = 0;
        core->reset = 1;
        tick();

        core->clock = 1;
        tick();

        core->reset = 0;
    }

    void tick() {
        if (!core->clock)
        {
            main_time++;
            ram.eval_posedge();
        }
        core->eval();
    }

    void next_tick() {
        core->clock = !core->clock;
        tick();
    }

    void halt() {
        core->final();               // Done simulating
    }
};

static struct option long_options[] = {
    {"load-image", required_argument, 0, 'l'},
    {"halt-addr", required_argument, 0, 'e'},
};


void die(const char *s) {
    fprintf(stderr, "error: %s\n", s);
    exit(1);
}

void ok_or_die(int ret, const char *s) {
    if (ret) die(s);
}

int main(int argc, char** argv) {
    int optidx = 0;
    auto soc = SoC(std::make_shared<Vcore>(), 0x8000, 0xc00000, 40 << 20);
    for (;;)
    {
        int c = getopt_long(argc, argv, "l:e", long_options, &optidx);
        if (c == -1) break;
        switch (c)
        {
            case 'l':
                {
                    std::string arg{optarg};
                    /*
                    auto pos = arg.find("=");
                    if (pos == std::string::npos)
                        die("invalid image spec, should be in the form of `<filename>=<hex location>`");
                    FILE *img = fopen(arg.substr(0, pos).c_str(), "r");
                    */
                    FILE *img = fopen(arg.c_str(), "r");
                    if (img)
                    {
                        size_t t;
                        /*
                        try {
                            auto loc = std::stoul(arg.substr(pos + 1), &t, 16);
                            soc.ram.load_image_from_file(img, loc);
                        } catch (...) {
                            die("invalid image location");
                        }
                        */
                            soc.ram.load_image_from_file(img, 0);
                        fclose(img);
                    } else
                        die("failed to open file");
                    break;
                }
            case 'e':
                {
                    size_t t;
                    try {
                        halt_addr = std::stoul(optarg, &t, 16);
                    } catch (...) {
                        die("invalid addr");
                    }
                    break;
                }
        }
    }
    Verilated::commandArgs(argc, argv);
    soc.reset();
    debug("reset\n");

    while (!Verilated::gotFinish()) {
        soc.next_tick();
        debug("===\n");
        if (soc.core->_debug_pc == halt_addr)
        {
            soc.halt();
            printf("halted the processor at 0x%x\n", halt_addr);
            break;
        }
   }
}
