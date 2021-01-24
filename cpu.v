`include "pipeline.v"
module cpu(
    input clock,
    input reset,

    output [31:0] icache_addr,
    input [31:0] icache_data,
    input icache_rdy,

    output [31:0] dcache_addr,
    input [31:0] dcache_rdata,
    output [31:0] dcache_wdata,
    input dcache_rdy,
    output dcache_en,
    output dcache_wr
);
    pipeline pl (
        clock,
        reset,
        icache_addr,
        icache_data,
        icache_rdy,
        dcache_addr,
        dcache_rdata,
        dcache_wdata,
        dcache_rdy,
        dcache_en,
        dcache_wr
    );
endmodule
