`include "csr_file.sv"
// opcode

`define LUI     7'b0110111
`define AUIPC   7'b0010111
`define JAL     7'b1101111
`define JALR    7'b1100111
`define BXX     7'b1100011 // BEQ, BNE, BLT, BGE, BLTU, BGEU
`define LX      7'b0000011 // LB, LH, LW, LBU, LHU
`define SX      7'b0100011 // SB, SH, SW
`define XXXI    7'b0010011 // ADDI, SLTI, SLTIU, XORI, ORI, ANDI, SLLI, SRLI, SRAI
`define XXX     7'b0110011 // ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND
`define SYS     7'b1110011 // ECALL, EBREAK, CSRx

// the following is not supported yet
`define FEN     7'b0001111 // FENCE

// funct3 code

`define FADD   3'b000
`define FSLT   3'b010
`define FSLTU  3'b011
`define FXOR   3'b100
`define FOR    3'b110
`define FAND   3'b111
`define FSLL   3'b001
`define FSRX   3'b101 // FSRLI & SRAI

`define FBEQ    3'b000
`define FBNE    3'b001
`define FBLT    3'b100
`define FBGE    3'b101
`define FBLTU   3'b110
`define FBGEU   3'b111

`define FB      3'b000
`define FH      3'b001
`define FW      3'b010
`define FBU     3'b100
`define FHU     3'b101

`define CSRRW   2'b01
`define CSRRS   2'b10
`define CSRRC   2'b11

`define EXC_REG_INS_ILL    0
`define EXC_REG_INS_ALIGN  1
`define EXC_REG_M_ECALL    2
`define EXC_REG_M_EBKPT    3
`define EXC_REG_ST_ALIGN   4
`define EXC_REG_LD_ALIGN   5

`define EXC_INS_ILL    2
`define EXC_INS_ALIGN  0
`define EXC_M_ECALL    11
`define EXC_M_EBKPT    3
`define EXC_ST_ALIGN   6
`define EXC_LD_ALIGN   4

`ifndef SYNTHESIS
    `ifdef DEBUG
        `define PIPELINE_DEBUG
    `endif
`endif

module register_file(
    input [4:0] reg1_raddr,
    input [4:0] reg2_raddr,
    output [31:0] reg1_rdata,
    output [31:0] reg2_rdata,

    input [4:0] reg_waddr,
    input [31:0] reg_wdata,
    input reg_wen, //< write enable

    input ctrl_clk //< clock
);
    // register file
    logic [31:0] regs [31:0];
    wire writing = reg_wen && reg_waddr != 0;
    assign reg1_rdata = writing && reg_waddr == reg1_raddr ? reg_wdata : regs[reg1_raddr];
    assign reg2_rdata = writing && reg_waddr == reg2_raddr ? reg_wdata : regs[reg2_raddr];
    assign regs[0] = 0;
    always_ff @ (posedge ctrl_clk) begin
        if (writing) begin
            `ifdef PIPELINE_DEBUG
                $display(
                    "[%0t] *[wb] write 0x%h to register %d",
                    $time, reg_wdata, reg_waddr
                );
            `endif
            regs[reg_waddr] <= reg_wdata;
        end else begin
            `ifdef PIPELINE_DEBUG
                $display("[%0t]  [wb] idle", $time);
            `endif
        end
    end
endmodule

module exception_code(
    input [5:0] eid,
    output [3:0] code
);
    assign code = eid[0] ? `EXC_INS_ILL :
                  eid[1] ? `EXC_INS_ALIGN :
                  eid[2] ? `EXC_M_ECALL :
                  eid[3] ? `EXC_M_EBKPT :
                  eid[4] ? `EXC_ST_ALIGN :
                  eid[5] ? `EXC_LD_ALIGN : 4'bx;
endmodule

module fetcher(
    input [31:0] pc_jump_target,
    input [31:0] pc_exc_target,

    input ctrl_clk,
    input ctrl_reset,
    input ctrl_stall,
    input ctrl_next_stage_stall,
    input ctrl_jump,
    input ctrl_exc,

    // i-cache communication
    output [31:0] icache_addr,
    output icache_req,
    input [31:0] icache_data,
    input icache_rdy,

    output logic [31:0] inst_reg,
    output logic [31:0] pc_reg,
    output logic [5:0] exc_reg,
    output logic ctrl_nop_reg,
    output ctrl_fetcher_stall
);
    logic [31:0] pc;

    wire ins_aligned = pc[1:0] == 0;
    assign icache_addr = pc;
    assign icache_req = ins_aligned;
    assign ctrl_fetcher_stall = ins_aligned && !icache_rdy;
    always_ff @ (posedge ctrl_clk) begin
        if (ctrl_reset) begin
            `ifdef PIPELINE_DEBUG
                $display("[%0t] reset pc", $time);
            `endif
            pc <= 32'h00000000; // initialize PC to 0x00000000
            ctrl_nop_reg <= 1;
        end else if (!ctrl_stall) begin
            `ifdef PIPELINE_DEBUG
                $display(
                    "[%0t] *[fetch] stage works on pc=0x%h jump=(0x%h,%b)",
                    $time, pc, pc_jump_target, ctrl_jump);
            `endif
            pc <= ctrl_exc ? pc_exc_target :
                  ctrl_jump ? pc_jump_target : (pc + 4);
            inst_reg <= icache_data;
            pc_reg <= pc;
            exc_reg <= {5'b0, !ins_aligned} << `EXC_REG_INS_ALIGN;
            ctrl_nop_reg <= 0;
        end else begin
            `ifdef PIPELINE_DEBUG
                $display("[%0t] =[fetch] stage stalls on pc=0x%h jump=(0x%h,%b)",
                    $time, pc, pc_jump_target, ctrl_jump);
            `endif
            if (!ctrl_next_stage_stall) // insert a bubble
                ctrl_nop_reg <= 1;
        end
    end
endmodule;

module decoder(
    input [31:0] inst,
    input [31:0] pc,
    input [5:0]  exc,

    input [31:0] reg1_rdata,
    input [31:0] reg2_rdata,
    input [31:0] csr_rdata,
    output [4:0] reg1_raddr,
    output [4:0] reg2_raddr,
    output [11:0] csr_raddr,

    // register forwarding
    input ctrl_forward_valid_exec,
    input [4:0] ctrl_forward_rd_exec,
    input [31:0] forward_data_exec,

    input ctrl_forward_valid_mem,
    input [4:0] ctrl_forward_rd_mem,
    input [31:0] forward_data_mem,
    input ctrl_forward_mload_stall,
    //
    
    // CSR forwarding
    input ctrl_forward_csr_valid_exec,
    input [11:0] ctrl_forward_csr_rd_exec,
    input [31:0] forward_csr_data_exec,

    input ctrl_forward_csr_valid_mem,
    input [11:0] ctrl_forward_csr_rd_mem,
    input [31:0] forward_csr_data_mem,
    // no stall as CSR instructions do not access memory
    //

    input ctrl_clk,
    input ctrl_reset,
    input ctrl_exc,
    input ctrl_stall,
    input ctrl_next_stage_stall,
    input ctrl_nop,

    // stage output data
    output logic [31:0] op1_reg,    // op1 for ALU
    output logic [31:0] op2_reg,    // op2 for ALU
    output logic [4:0] rd_reg,      // destination general register for writeback
    output logic [11:0] rd_csr_reg, // destination CSR register for writeback
    output logic [31:0] tmp_reg,    // keeps some additional value that skips ALU
    output logic [31:0] pc_reg,     // pass on the instruction address
    output logic [5:0] exc_reg,     // exceptions

    output logic [2:0] ctrl_alu_func_reg,
    output logic ctrl_alu_sign_ext_reg,
    output logic ctrl_nop_reg,
    output logic ctrl_wb_reg,
    output logic ctrl_wb_csr_reg,
    output logic [4:0] ctrl_mem_reg,
    output [31:0] ctrl_pc_jump_target,
    output ctrl_jump,
    output ctrl_decoder_stall
);
    // Layout: [  7 bits          ][5 bits][5 bits][3 bits][ 5 bits         ][ 7 bits ]
    // R-type: [funct7            ][rs2   ][rs1   ][funct3][rd              ][opcode  ]
    //
    // I-type: [    imm[11:0]             ][rs1   ][funct3][rd              ][opcode  ]
    // S-type: [imm[11:5]         ][rs2   ][rs1   ][funct3][imm[4:0]        ][opcode  ]
    // B-type: [imm[12]][imm[10:5]]........................[imm[4:1][imm[11]]..........
    // U-type: [                imm[31:12]                ][rd              ][opcode  ]
    // J-type: [imm[20]][ imm[10:1] ][imm[11]][imm[19:12] ]............................
    //          ^
    //          |____ sign

    // instruction fields
    logic ctrl_skip_next_reg;
    wire [6:0] opcode = inst[6:0];
    wire [2:0] funct3 = inst[14:12];
    wire [4:0] rs1 = inst[19:15];
    wire [4:0] rs2 = inst[24:20];
    wire [4:0] rd = inst[11:7];
    wire [31:0] ui = {inst[31:12], 12'b0}; //< load upper immediate
    wire [31:0] xxxi = {{20{inst[31]}}, inst[31:20]}; //< sign-extended immediate
    wire [20:0] jal_offset = {inst[31], inst[19:12], inst[20], inst[30:21], 1'b0};
    wire [11:0] jalr_offset = inst[31:20];
    wire [12:0] b_offset = {inst[31], inst[7], inst[30:25], inst[11:8], 1'b0};
    wire [11:0] l_offset = inst[31:20];
    wire [11:0] s_offset = {inst[31:25], inst[11:7]};
    wire [11:0] csr = inst[31:20];
    wire is_nop = ctrl_nop ||
                  ctrl_skip_next_reg ||
                  ctrl_exc ||
                  (opcode == `XXXI && inst[31:7] == 0) ||
                  opcode == `FEN;

    assign ctrl_decoder_stall = ctrl_forward_mload_stall &&
                                (((opcode == `XXXI ||
                                  opcode == `XXX ||
                                  opcode == `LX ||
                                  opcode == `SX ||
                                  opcode == `JALR ||
                                  opcode == `BXX ||
                                  opcode == `SYS) && ctrl_forward_rd_exec == rs1) ||
                                ((opcode == `XXX ||
                                  opcode == `SX ||
                                  opcode == `JALR ||
                                  opcode == `BXX) && ctrl_forward_rd_exec == rs2));

    // wire to read from register file
    assign reg1_raddr = rs1;
    assign reg2_raddr = rs2;

    wire [31:0] op1 = (ctrl_forward_valid_exec && rs1 == ctrl_forward_rd_exec) ? forward_data_exec:
                      (ctrl_forward_valid_mem && rs1 == ctrl_forward_rd_mem) ? forward_data_mem:
                                                                               reg1_rdata;
    wire [31:0] op2 = (ctrl_forward_valid_exec && rs2 == ctrl_forward_rd_exec) ? forward_data_exec:
                      (ctrl_forward_valid_mem && rs2 == ctrl_forward_rd_mem) ? forward_data_mem:
                                                                               reg2_rdata;
    // CSR
    assign csr_raddr = csr;
    wire [31:0] csr_op = (ctrl_forward_csr_valid_exec && csr == ctrl_forward_csr_rd_exec) ? forward_csr_data_exec:
                          (ctrl_forward_csr_valid_mem && csr == ctrl_forward_csr_rd_mem) ? forward_csr_data_mem:
                                                                                            csr_rdata;
    wire [1:0] csr_func = funct3[1:0];
    wire [31:0] csr_tmp = funct3[2] ? {27'b0, rs1} : op1;

    // set jump signal for control transfer instructions
    assign ctrl_pc_jump_target =
        opcode == `JAL ? pc + $signed({{11{jal_offset[20]}}, jal_offset}) :
        opcode == `JALR ? op1 + $signed({{20{jalr_offset[11]}}, jalr_offset}):
        opcode == `BXX ? pc + $signed({{19{b_offset[12]}}, b_offset}) : 'bx;
    assign ctrl_jump = (!ctrl_skip_next_reg) &&
        (opcode == `JAL ? 1 :
        opcode == `JALR ? 1 :
        opcode == `BXX ?
              funct3[2:1] == 0 ? ((op1 == op2) ^ (funct3[0])) : // BEQ & BNE
               (funct3[1] == 0 ?
                  (($signed(op1) < $signed(op2)) ^ (funct3[0])) : // BLT & BGE
                  ((op1 < op2) ^ (funct3[0]))) : 0); // BLTU & BGEU

    always_ff @ (posedge ctrl_clk) begin
        if (ctrl_reset) begin
            ctrl_skip_next_reg <= 0;
            ctrl_nop_reg <= 1;
        end else if (!ctrl_stall) begin
            if (!is_nop) begin
                `ifdef PIPELINE_DEBUG
                    $display(
                        "[%0t] *[decode] stage works on inst=0x%h pc=0x%h rs1=0x%h rs2=0x%h skip=%b",
                        $time, inst, pc, op1, op2, ctrl_skip_next_reg);
                `endif
                case (opcode)
                    `XXXI: begin
                        op1_reg <= op1;
                        op2_reg <= xxxi;
                        exc_reg <= exc;
                        ctrl_alu_func_reg <= funct3;
                        ctrl_alu_sign_ext_reg <= funct3 == `FSRX ? inst[30] : 0;
                        ctrl_wb_reg <= 1;
                        ctrl_mem_reg <= 0;
                    end
                    `XXX: begin
                        op1_reg <= op1;
                        op2_reg <= op2;
                        exc_reg <= exc;
                        ctrl_alu_func_reg <= funct3;
                        ctrl_alu_sign_ext_reg <= inst[30];
                        ctrl_wb_reg <= 1;
                        ctrl_mem_reg <= 0;
                    end
                    `LUI: begin
                        op1_reg <= ui;
                        op2_reg <= 0;
                        exc_reg <= exc;
                        ctrl_alu_func_reg <= `FADD;
                        ctrl_alu_sign_ext_reg <= 0;
                        ctrl_wb_reg <= 1;
                        ctrl_mem_reg <= 0;
                    end
                    `AUIPC: begin
                        op1_reg <= ui;
                        op2_reg <= pc;
                        exc_reg <= exc;
                        ctrl_alu_func_reg <= `FADD;
                        ctrl_alu_sign_ext_reg <= 0;
                        ctrl_wb_reg <= 1;
                        ctrl_mem_reg <= 0;
                    end
                    `LX: begin
                        op1_reg <= op1;
                        op2_reg <= {{20{l_offset[11]}}, l_offset};
                        exc_reg <= exc;
                        ctrl_alu_func_reg <= `FADD;
                        ctrl_alu_sign_ext_reg <= 0;
                        ctrl_wb_reg <= 1;
                        ctrl_mem_reg <= {funct3, 2'b10};
                    end
                    `SX: begin
                        op1_reg <= op1;
                        op2_reg <= {{20{s_offset[11]}}, s_offset};
                        exc_reg <= exc;
                        tmp_reg <= op2;
                        ctrl_alu_func_reg <= `FADD;
                        ctrl_alu_sign_ext_reg <= 0;
                        ctrl_wb_reg <= 0;
                        ctrl_mem_reg <= {funct3, 2'b11};
                    end
                    `JAL, `JALR: begin
                        op1_reg <= pc;
                        op2_reg <= 4;
                        exc_reg <= exc;
                        ctrl_alu_func_reg <= `FADD;
                        ctrl_alu_sign_ext_reg <= 0;
                        ctrl_wb_reg <= 1;
                        ctrl_mem_reg <= 0; //{funct3, 2'b00};
                    end
                    `SYS: begin
                        op1_reg <= csr_op;
                        op2_reg <= 0;
                        exc_reg <= exc;
                        rd_csr_reg <= csr;
                        ctrl_alu_func_reg <= `FADD;
                        ctrl_alu_sign_ext_reg <= 0;
                        ctrl_wb_reg <= funct3 != 0; // all CSR instructions writes to rd
                        ctrl_mem_reg <= 0;
                        // CSR
                        tmp_reg <=
                            csr_func == `CSRRW ? csr_tmp :
                            csr_func == `CSRRS ? (csr_rdata | csr_tmp) :
                            csr_func == `CSRRC ? (csr_rdata & (~csr_tmp)) : 'bx;
                        ctrl_wb_csr_reg <= csr_func != 0 && rs1 != 0;
                    end
                    `BXX: begin
                        exc_reg <= exc;
                        ctrl_wb_reg <= 0;
                        ctrl_mem_reg <= 0;
                    end
                    default: begin // WIP: illegal instruction detection
                        exc_reg <= exc | (1 << `EXC_REG_INS_ILL);
                        ctrl_wb_reg <= 0;
                        ctrl_mem_reg <= 0;
                    end
                endcase
                rd_reg <= rd;
                pc_reg <= pc;
                ctrl_skip_next_reg <= ctrl_jump;
            end else begin // NOP or a bubble
                `ifdef PIPELINE_DEBUG
                    $display("[%0t]  [decode] stage idle", $time);
                `endif
                ctrl_skip_next_reg <= 0;
            end
            ctrl_nop_reg <= is_nop;
        end else begin // stalled
            `ifdef PIPELINE_DEBUG
                $display(
                    "[%0t] =[decode] stage stalls on inst=0x%h pc=0x%h rs1=0x%h rs2=0x%h skip=%b",
                    $time, inst, pc, op1, op2, ctrl_skip_next_reg);
            `endif
            if (!ctrl_next_stage_stall) // insert a bubble
                ctrl_nop_reg <= 1;
        end
    end
endmodule

module executor(
    input [31:0] op1,
    input [31:0] op2,
    input [4:0] rd,
    input [11:0] rd_csr,
    input [31:0] tmp,
    input [31:0] pc,
    input [5:0] exc,

    input ctrl_clk,
    input ctrl_reset,
    input ctrl_exc,
    input ctrl_stall,
    input ctrl_next_stage_stall,
    input [2:0] ctrl_alu_func,
    input ctrl_alu_sign_ext,
    input ctrl_nop,
    input ctrl_wb,
    input ctrl_wb_csr,
    input [4:0] ctrl_mem,

    // stage output data
    output logic [31:0] res_reg,    // the result from ALU
    output logic [4:0] rd_reg,
    output logic [11:0] rd_csr_reg,
    output logic [31:0] tmp_reg,
    output logic [31:0] pc_reg,
    output logic [5:0] exc_reg,

    output logic ctrl_nop_reg,
    output logic ctrl_wb_reg,
    output logic ctrl_wb_csr_reg,
    output logic [4:0] ctrl_mem_reg,

    output ctrl_forward_valid,
    output [4:0] ctrl_forward_rd,
    output [31:0] forward_data,
    output ctrl_forward_mload_stall,

    output ctrl_forward_csr_valid,
    output [11:0] ctrl_forward_csr_rd,
    output [31:0] forward_csr_data,

    output ctrl_executor_stall
);
    wire is_nop = ctrl_nop || ctrl_exc;
    assign ctrl_executor_stall = 0;
    // the second clause is for LX (has to wait after memory load, and ALU's result should be ignored)
    assign ctrl_forward_valid = (!is_nop) && ctrl_wb && (!ctrl_mem[1]);
    assign ctrl_forward_mload_stall = (!is_nop) && ctrl_mem[1:0] == 2'b10;
    assign ctrl_forward_rd = rd;
    assign forward_data = res;

    assign ctrl_forward_csr_valid = (!is_nop) && ctrl_wb_csr;
    assign ctrl_forward_csr_rd = rd_csr;
    assign forward_csr_data = tmp;

    // ALU
    wire [31:0] res = ctrl_alu_func == `FADD ? (ctrl_alu_sign_ext ? op1 - op2 : op1 + op2) :
               ctrl_alu_func == `FSLT ? ($signed(op1) < $signed(op2) ? 1 : 0) :
               ctrl_alu_func == `FSLTU ? (op1 < op2 ? 1 : 0) :
               ctrl_alu_func == `FXOR ? (op1 ^ op2) :
               ctrl_alu_func == `FOR ? (op1 | op2) :
               ctrl_alu_func == `FAND ? (op1 & op2) :
               ctrl_alu_func == `FSLL ? (op1 << op2[4:0]) :
               ctrl_alu_func == `FSRX ? (ctrl_alu_sign_ext ? $signed(op1) >> op2[4:0] : op1 >> op2[4:0]) : 'bx;

    always_ff @ (posedge ctrl_clk) begin
        if (ctrl_reset)
            ctrl_nop_reg <= 1;
        else if (!ctrl_stall) begin
            if (!is_nop) begin
                `ifdef PIPELINE_DEBUG
                    $display(
                        "[%0t] *[execution] stage works on op1=0x%h op2=0x%h tmp=0x%h rd=%d sign=%b",
                        $time, op1, op2, tmp, rd, ctrl_alu_sign_ext
                    );
                `endif
                res_reg <= res;
                rd_reg <= rd;
                rd_csr_reg <= rd_csr;
                tmp_reg <= tmp;
                pc_reg <= pc;
                exc_reg <= exc;
                ctrl_wb_reg <= ctrl_wb;
                ctrl_wb_csr_reg <= ctrl_wb_csr;
                ctrl_mem_reg <= ctrl_mem;
            end else begin
                `ifdef PIPELINE_DEBUG
                    $display("[%0t]  [execution] stage idle", $time);
                `endif
            end
            ctrl_nop_reg <= is_nop;
        end else begin
            `ifdef PIPELINE_DEBUG
                $display(
                    "[%0t] =[execution] stage stalls on op1=0x%h op2=0x%h tmp=0x%h rd=%d sign=%b",
                    $time, op1, op2, tmp, rd, ctrl_alu_sign_ext
                );
            `endif
            if (!ctrl_next_stage_stall)
                ctrl_nop_reg <= 1;
        end
    end
endmodule

module memory(
    input [31:0] res_alu,
    input [4:0] rd,
    input [11:0] rd_csr,
    input [31:0] tmp,
    input [31:0] pc,
    input [5:0] exc,

    // d-cache communication
    output [31:0] dcache_addr,
    output [31:0] dcache_wdata,
    output [1:0] dcache_ws,
    output dcache_req,
    output dcache_wr,
    input [31:0] dcache_rdata,
    input dcache_rdy,

    input ctrl_clk,
    input ctrl_reset,
    input ctrl_exc,
    input ctrl_stall,
    input ctrl_next_stage_stall,
    input ctrl_wb,
    input ctrl_wb_csr,
    input ctrl_nop,
    input [4:0] ctrl_mem,

    // statge output data
    output logic [31:0] res_reg,
    output logic [4:0] rd_reg,
    output logic [11:0] rd_csr_reg,
    output logic [31:0] tmp_reg,
    output logic [31:0] pc_reg,
    output logic [5:0] exc_reg,

    output logic ctrl_nop_reg,
    output logic ctrl_wb_reg,
    output logic ctrl_wb_csr_reg,

    output ctrl_forward_valid,
    output [4:0] ctrl_forward_rd,
    output [31:0] forward_data,

    output ctrl_forward_csr_valid,
    output [11:0] ctrl_forward_csr_rd,
    output [31:0] forward_csr_data,

    output ctrl_mem_stall
);
    wire is_nop = ctrl_nop || ctrl_exc;
    assign dcache_req = (!is_nop) && ctrl_mem[1] && exc == 0;
    assign dcache_wr = ctrl_mem[0];
    assign dcache_ws = ctrl_mem[3:2]; // SB/SH/SW
    assign dcache_wdata = tmp;
    assign dcache_addr = res_alu;

    assign ctrl_mem_stall = dcache_req && (!dcache_rdy);

    assign ctrl_forward_valid = (!is_nop) && ctrl_wb;
    assign ctrl_forward_rd = rd;
    assign forward_data = res;

    assign ctrl_forward_csr_valid = (!is_nop) && ctrl_wb_csr;
    assign ctrl_forward_csr_rd = rd_csr;
    assign forward_csr_data = tmp;

    wire sgn = ctrl_mem[4];

    wire [31:0] res_mem =
        dcache_ws == 2'b00 ? {{24{sgn ? dcache_rdata[7] : 1'b0}}, dcache_rdata[7:0]} : // LB/LBU
        dcache_ws == 2'b01 ? {{16{sgn ? dcache_rdata[15] : 1'b0}}, dcache_rdata[15:0]} : // LH/LHU
        dcache_ws == 2'b10 ? dcache_rdata : // LW
                            'bx;
    wire [31:0] res = (ctrl_mem[1:0] == 2'b10) ? res_mem : res_alu;

    always_ff @ (posedge ctrl_clk) begin
        if (ctrl_reset)
            ctrl_nop_reg <= 1;
        else if (!ctrl_stall) begin
            if (!is_nop) begin
                `ifdef PIPELINE_DEBUG
                    $display(
                        "[%0t] *[memory] stage works on res_alu=0x%h tmp=0x%h rd=%d ctrl_wb=%b ctrl_mem=%5b",
                        $time, res_alu, tmp, rd, ctrl_wb, ctrl_mem
                    );
                `endif
                res_reg <= res;
                rd_reg <= rd;
                rd_csr_reg <= rd_csr;
                tmp_reg <= tmp;
                pc_reg <= pc;
                exc_reg <= exc;
                ctrl_wb_reg <= ctrl_wb;
                ctrl_wb_csr_reg <= ctrl_wb_csr;
            end else begin
                `ifdef PIPELINE_DEBUG
                    $display("[%0t]  [memory] stage idle", $time);
                `endif
            end
            ctrl_nop_reg <= is_nop;
        end else begin
            `ifdef PIPELINE_DEBUG
                $display(
                    "[%0t] =[memory] stage stalls on res_alu=0x%h tmp=0x%h rd=%d ctrl_wb=%b ctrl_mem=%5b",
                    $time, res_alu, tmp, rd, ctrl_wb, ctrl_mem);
            `endif
            if (!ctrl_next_stage_stall)
                ctrl_nop_reg <= 1;
        end
    end
endmodule

module writeback(
    input [31:0] res,
    input [4:0] rd,
    input [11:0] rd_csr,
    input [31:0] tmp,
    input [31:0] pc,
    input [5:0] exc,

    input ctrl_stall,
    input ctrl_wb,
    input ctrl_wb_csr,
    input ctrl_nop,

    // Reg file
    output [4:0] reg_waddr,
    output [31:0] reg_wdata,
    output reg_wen,

    // CSR
    output [11:0] csr_raddr,
    input [31:0] csr_rdata,
    output [11:0] csr_waddr,
    output [31:0] csr_wdata,
    output csr_wen,
    output [31:0] csr_pc,

    output ctrl_writeback_stall,
    output ctrl_exc,
    output [31:0] ctrl_pc_exc_target
);
    assign ctrl_exc = !ctrl_nop && exc != 0;
    wire valid = !ctrl_stall && !ctrl_exc;

    // write back registers
    assign reg_waddr = rd;
    assign reg_wdata = res;
    assign reg_wen = valid && ctrl_wb;
    assign ctrl_writeback_stall = 0;

    assign csr_waddr = rd_csr;
    assign csr_wdata = tmp;
    assign csr_wen = valid && ctrl_wb_csr;

    // If there is an exception:
    // 1. change PC of fetcher for the next cycle according to mtvec.
    // 2. mark all instructions in previous stages as NOP.
    // 3. push a special flag to writeback stage (so it writes back all CSR changes in the next cycle).
    exception_code _code(exc, cause);
    wire [31:0] mtvec_base = {csr_rdata[31:2], 2'b00};
    wire [3:0] cause;
    assign csr_raddr = `CSR_MTVEC;
    assign csr_pc = pc;
    assign ctrl_pc_exc_target = csr_rdata[0] ? (mtvec_base + ({28'b0, cause} << 2)) : mtvec_base;
endmodule

module pipeline (
    input clock,
    input reset,
    output [31:0] _debug_pc,

    // i-cache communication
    output [31:0] icache_addr,
    output icache_req,
    input [31:0] icache_data,
    input icache_rdy,

    // d-cache communication
    output [31:0] dcache_addr,
    output [31:0] dcache_wdata,
    output [1:0] dcache_ws,
    output dcache_req,
    output dcache_wr,
    input [31:0] dcache_rdata,
    input dcache_rdy
);
    // program counter

    wire [31:0] pc_jump_target;
    wire [31:0] pc_exc_target;
    wire ctrl_jump;
    wire ctrl_exc;
    wire ctrl_fetcher_stall;
    wire ctrl_decoder_stall;
    wire ctrl_executor_stall;
    wire ctrl_mem_stall;
    wire ctrl_writeback_stall;
    wire [4:0] reg1_raddr;
    wire [4:0] reg2_raddr;
    wire [31:0] reg1_rdata;
    wire [31:0] reg2_rdata;
    wire [4:0] reg_waddr;
    wire [31:0] reg_wdata;
    wire reg_wen;

    wire [11:0] csr_raddr1;
    wire [11:0] csr_raddr2;
    wire [31:0] csr_rdata1;
    wire [31:0] csr_rdata2;
    wire [11:0] csr_waddr;
    wire [31:0] csr_wdata;
    wire csr_wen;
    wire [31:0] csr_pc;


    csr_file csr_reg(
        .raddr1(csr_raddr1),
        .raddr2(csr_raddr2),
        .rdata1(csr_rdata1),
        .rdata2(csr_rdata2),
        .waddr(csr_waddr),
        .wdata(csr_wdata),
        .wen(csr_wen),
        .pc(csr_pc),
        .ctrl_clk(clock),
        .ctrl_reset(reset),
        .ctrl_trap(ctrl_exc),
        .ctrl_mie(),
        .ctrl_mpie()
    );

    register_file main_reg(
        .reg1_raddr(reg1_raddr),
        .reg2_raddr(reg2_raddr),
        .reg1_rdata(reg1_rdata),
        .reg2_rdata(reg2_rdata),
        .reg_waddr(reg_waddr),
        .reg_wdata(reg_wdata),
        .reg_wen(reg_wen),
        .ctrl_clk(clock)
    );

    wire ctrl_fetcher_stall_in = ctrl_fetcher_stall ||
                                 ctrl_decoder_stall ||
                                 ctrl_executor_stall ||
                                 ctrl_mem_stall ||
                                 ctrl_writeback_stall;

    wire ctrl_decoder_stall_in = ctrl_decoder_stall ||
                                 ctrl_fetcher_stall || // because jumps could change PC
                                 ctrl_executor_stall ||
                                 ctrl_mem_stall ||
                                 ctrl_writeback_stall;

    wire ctrl_executor_stall_in = ctrl_executor_stall ||
                                  ctrl_mem_stall ||
                                  ctrl_writeback_stall;

    wire ctrl_mem_stall_in = ctrl_mem_stall ||
                             ctrl_writeback_stall;

    wire [31:0] inst_if_o;
    wire [31:0] pc_if_o;
    wire [5:0] exc_if_o;
    wire ctrl_nop_if_o;

    fetcher if_stage(
        .pc_jump_target(pc_jump_target),
        .pc_exc_target(pc_exc_target),

        .ctrl_clk(clock),
        .ctrl_reset(reset),
        .ctrl_stall(ctrl_fetcher_stall_in),
        .ctrl_next_stage_stall(ctrl_decoder_stall_in),
        .ctrl_jump(ctrl_jump),
        .ctrl_exc(ctrl_exc),

        .icache_addr(icache_addr),
        .icache_req(icache_req),
        .icache_data(icache_data),
        .icache_rdy(icache_rdy),

        .inst_reg(inst_if_o),
        .pc_reg(pc_if_o),
        .exc_reg(exc_if_o),

        .ctrl_nop_reg(ctrl_nop_if_o),
        .ctrl_fetcher_stall(ctrl_fetcher_stall)
    );

    wire [31:0] op1_id_o;
    wire [31:0] op2_id_o;
    wire [4:0] rd_id_o;
    wire [11:0] rd_csr_id_o;
    wire [31:0] tmp_id_o;
    wire [31:0] pc_id_o;
    wire [5:0] exc_id_o;

    wire [2:0] ctrl_alu_func_id_o;
    wire ctrl_alu_sign_ext_id_o;
    wire ctrl_nop_id_o;
    wire ctrl_wb_id_o;
    wire ctrl_wb_csr_id_o;
    wire [4:0] ctrl_mem_id_o;

    wire ctrl_forward_valid_exec;
    wire [4:0] ctrl_forward_rd_exec;
    wire [31:0] forward_data_exec;
    wire ctrl_forward_mload_stall;

    wire ctrl_forward_valid_mem;
    wire [4:0] ctrl_forward_rd_mem;
    wire [31:0] forward_data_mem;

    wire ctrl_forward_csr_valid_exec;
    wire [11:0] ctrl_forward_csr_rd_exec;
    wire [31:0] forward_csr_data_exec;

    wire ctrl_forward_csr_valid_mem;
    wire [11:0] ctrl_forward_csr_rd_mem;
    wire [31:0] forward_csr_data_mem;

    decoder id_stage(
        .inst(inst_if_o),
        .pc(pc_if_o),
        .exc(exc_if_o),

        .reg1_rdata(reg1_rdata),
        .reg2_rdata(reg2_rdata),
        .csr_rdata(csr_rdata1),
        .reg1_raddr(reg1_raddr),
        .reg2_raddr(reg2_raddr),
        .csr_raddr(csr_raddr1),

        .ctrl_forward_valid_exec(ctrl_forward_valid_exec),
        .ctrl_forward_rd_exec(ctrl_forward_rd_exec),
        .forward_data_exec(forward_data_exec),

        .ctrl_forward_valid_mem(ctrl_forward_valid_mem),
        .ctrl_forward_rd_mem(ctrl_forward_rd_mem),
        .forward_data_mem(forward_data_mem),
        .ctrl_forward_mload_stall(ctrl_forward_mload_stall),

        .ctrl_forward_csr_valid_exec(ctrl_forward_csr_valid_exec),
        .ctrl_forward_csr_rd_exec(ctrl_forward_csr_rd_exec),
        .forward_csr_data_exec(forward_csr_data_exec),

        .ctrl_forward_csr_valid_mem(ctrl_forward_csr_valid_mem),
        .ctrl_forward_csr_rd_mem(ctrl_forward_csr_rd_mem),
        .forward_csr_data_mem(forward_csr_data_mem),

        .ctrl_clk(clock),
        .ctrl_reset(reset),
        .ctrl_exc(ctrl_exc),
        .ctrl_stall(ctrl_decoder_stall_in),
        .ctrl_next_stage_stall(ctrl_executor_stall_in),
        .ctrl_nop(ctrl_nop_if_o),

        .op1_reg(op1_id_o),
        .op2_reg(op2_id_o),
        .rd_reg(rd_id_o),
        .rd_csr_reg(rd_csr_id_o),
        .tmp_reg(tmp_id_o),
        .pc_reg(pc_id_o),
        .exc_reg(exc_id_o),

        .ctrl_alu_func_reg(ctrl_alu_func_id_o),
        .ctrl_alu_sign_ext_reg(ctrl_alu_sign_ext_id_o),
        .ctrl_nop_reg(ctrl_nop_id_o),
        .ctrl_wb_reg(ctrl_wb_id_o),
        .ctrl_wb_csr_reg(ctrl_wb_csr_id_o),
        .ctrl_mem_reg(ctrl_mem_id_o),
        .ctrl_pc_jump_target(pc_jump_target),
        .ctrl_jump(ctrl_jump),
        .ctrl_decoder_stall(ctrl_decoder_stall)
    );

    wire [31:0] res_ex_o;
    wire [4:0] rd_ex_o;
    wire [11:0] rd_csr_ex_o;
    wire [31:0] tmp_ex_o;
    wire [31:0] pc_ex_o;
    wire [5:0] exc_ex_o;
    wire ctrl_nop_ex_o;
    wire ctrl_wb_ex_o;
    wire ctrl_wb_csr_ex_o;
    wire [4:0] ctrl_mem_ex_o;

    executor ex_stage(
        .op1(op1_id_o),
        .op2(op2_id_o),
        .rd(rd_id_o),
        .rd_csr(rd_csr_id_o),
        .tmp(tmp_id_o),
        .pc(pc_id_o),
        .exc(exc_id_o),

        .ctrl_clk(clock),
        .ctrl_reset(reset),
        .ctrl_exc(ctrl_exc),
        .ctrl_stall(ctrl_executor_stall_in),
        .ctrl_next_stage_stall(ctrl_mem_stall_in),
        .ctrl_alu_func(ctrl_alu_func_id_o),
        .ctrl_alu_sign_ext(ctrl_alu_sign_ext_id_o),
        .ctrl_nop(ctrl_nop_id_o),
        .ctrl_wb(ctrl_wb_id_o),
        .ctrl_wb_csr(ctrl_wb_csr_id_o),
        .ctrl_mem(ctrl_mem_id_o),

        .res_reg(res_ex_o),
        .rd_reg(rd_ex_o),
        .rd_csr_reg(rd_csr_ex_o),
        .tmp_reg(tmp_ex_o),
        .pc_reg(pc_ex_o),
        .exc_reg(exc_ex_o),

        .ctrl_nop_reg(ctrl_nop_ex_o),
        .ctrl_wb_reg(ctrl_wb_ex_o),
        .ctrl_wb_csr_reg(ctrl_wb_csr_ex_o),
        .ctrl_mem_reg(ctrl_mem_ex_o),

        .ctrl_forward_valid(ctrl_forward_valid_exec),
        .ctrl_forward_rd(ctrl_forward_rd_exec),
        .forward_data(forward_data_exec),
        .ctrl_forward_mload_stall(ctrl_forward_mload_stall),

        .ctrl_forward_csr_valid(ctrl_forward_csr_valid_exec),
        .ctrl_forward_csr_rd(ctrl_forward_csr_rd_exec),
        .forward_csr_data(forward_csr_data_exec),

        .ctrl_executor_stall(ctrl_executor_stall)
    );

    wire [31:0] res_mem_o;
    wire [4:0] rd_mem_o;
    wire [11:0] rd_csr_mem_o;
    wire [31:0] tmp_mem_o;
    wire [31:0] pc_mem_o;
    wire [5:0] exc_mem_o;

    wire ctrl_nop_mem_o;
    wire ctrl_wb_mem_o;
    wire ctrl_wb_csr_mem_o;

    memory mem_stage(
        .res_alu(res_ex_o),
        .rd(rd_ex_o),
        .rd_csr(rd_csr_ex_o),
        .tmp(tmp_ex_o),
        .pc(pc_ex_o),
        .exc(exc_ex_o),

        .dcache_addr(dcache_addr),
        .dcache_wdata(dcache_wdata),
        .dcache_ws(dcache_ws),
        .dcache_req(dcache_req),
        .dcache_wr(dcache_wr),
        .dcache_rdata(dcache_rdata),
        .dcache_rdy(dcache_rdy),

        .ctrl_clk(clock),
        .ctrl_reset(reset),
        .ctrl_exc(ctrl_exc),
        .ctrl_stall(ctrl_mem_stall_in),
        .ctrl_next_stage_stall(0),
        .ctrl_nop(ctrl_nop_ex_o),
        .ctrl_wb(ctrl_wb_ex_o),
        .ctrl_wb_csr(ctrl_wb_csr_ex_o),
        .ctrl_mem(ctrl_mem_ex_o),

        .res_reg(res_mem_o),
        .rd_reg(rd_mem_o),
        .rd_csr_reg(rd_csr_mem_o),
        .tmp_reg(tmp_mem_o),
        .pc_reg(pc_mem_o),
        .exc_reg(exc_mem_o),

        .ctrl_nop_reg(ctrl_nop_mem_o),
        .ctrl_wb_reg(ctrl_wb_mem_o),
        .ctrl_wb_csr_reg(ctrl_wb_csr_mem_o),

        .ctrl_forward_valid(ctrl_forward_valid_mem),
        .ctrl_forward_rd(ctrl_forward_rd_mem),
        .forward_data(forward_data_mem),

        .ctrl_forward_csr_valid(ctrl_forward_csr_valid_mem),
        .ctrl_forward_csr_rd(ctrl_forward_csr_rd_mem),
        .forward_csr_data(forward_csr_data_mem),

        .ctrl_mem_stall(ctrl_mem_stall)
    );

    writeback wb_stage(
        .res(res_mem_o),
        .rd(rd_mem_o),
        .rd_csr(rd_csr_mem_o),
        .tmp(tmp_mem_o),
        .pc(pc_mem_o),
        .exc(exc_mem_o),

        .ctrl_stall(0),
        .ctrl_wb(ctrl_wb_mem_o),
        .ctrl_wb_csr(ctrl_wb_csr_mem_o),
        .ctrl_nop(ctrl_nop_mem_o),

        .reg_waddr(reg_waddr),
        .reg_wdata(reg_wdata),
        .reg_wen(reg_wen),

        .csr_raddr(csr_raddr2),
        .csr_rdata(csr_rdata2),
        .csr_waddr(csr_waddr),
        .csr_wdata(csr_wdata),
        .csr_wen(csr_wen),
        .csr_pc(csr_pc),

        .ctrl_writeback_stall(ctrl_writeback_stall),
        .ctrl_exc(ctrl_exc),
        .ctrl_pc_exc_target(pc_exc_target)
    );

    assign _debug_pc = ctrl_nop_mem_o ? 'hffffffff : pc_mem_o;
endmodule
