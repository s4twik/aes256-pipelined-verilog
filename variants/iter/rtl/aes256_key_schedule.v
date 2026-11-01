`timescale 1ns / 1ps
`default_nettype none

// Sequential AES-256 key expansion.
//
// A 256-bit key consists of eight 32-bit words and directly provides RK0/RK1.
// This unit then generates one additional 128-bit round key per clock. It takes
// 13 clocks after key_load to produce RK2 through RK14. All 15 round keys remain
// available in parallel for the fully pipelined encryption datapath.
module aes256_key_schedule (
    input  wire          clk,
    input  wire          reset,
    input  wire          key_load,
    input  wire [255:0]  key_in,

    output reg           key_busy,
    output reg           key_ready,
    output wire [1919:0] round_keys_flat
);

    // round_keys[0] through round_keys[14], each 128 bits.
    reg [127:0] round_keys [0:14];

    // Two adjacent 128-bit halves form the current eight-word key window.
    reg [127:0] key_half_a;
    reg [127:0] key_half_b;

    // phase_g=1 applies RotWord, SubWord and Rcon.
    // phase_g=0 applies the AES-256-specific SubWord-only transformation.
    reg         phase_g;
    reg [3:0]   next_round;
    reg [7:0]   rcon;

    wire [31:0] sbox_word_in;
    wire [31:0] sub_word;
    wire [31:0] transformed_word;
    wire [127:0] base_half;
    wire [127:0] expanded_half;

    // For a G phase, rotate the final word of half B by one byte.
    // For an H phase, substitute the final word of the newly generated half A.
    assign sbox_word_in = phase_g
                        ? {key_half_b[23:0], key_half_b[31:24]}
                        : key_half_a[31:0];

    aes_sbox u_key_sbox0 (
        .data_in  (sbox_word_in[31:24]),
        .data_out (sub_word[31:24])
    );

    aes_sbox u_key_sbox1 (
        .data_in  (sbox_word_in[23:16]),
        .data_out (sub_word[23:16])
    );

    aes_sbox u_key_sbox2 (
        .data_in  (sbox_word_in[15:8]),
        .data_out (sub_word[15:8])
    );

    aes_sbox u_key_sbox3 (
        .data_in  (sbox_word_in[7:0]),
        .data_out (sub_word[7:0])
    );

    assign transformed_word = sub_word ^
                              (phase_g ? {rcon, 24'h000000} : 32'h00000000);

    assign base_half = phase_g ? key_half_a : key_half_b;

    // Generate four new words. Each word depends on the word immediately
    // before it, exactly as specified by the AES key-expansion recurrence.
    wire [31:0] new_word0 = base_half[127:96] ^ transformed_word;
    wire [31:0] new_word1 = base_half[95:64]  ^ new_word0;
    wire [31:0] new_word2 = base_half[63:32]  ^ new_word1;
    wire [31:0] new_word3 = base_half[31:0]   ^ new_word2;

    assign expanded_half = {new_word0, new_word1, new_word2, new_word3};

    // AES round constants are multiplied by 02 in GF(2^8).
    wire [7:0] next_rcon = {rcon[6:0], 1'b0} ^ (8'h1b & {8{rcon[7]}});

    // Flatten the internal key array for a Verilog-2001-compatible port.
    genvar key_index;
    generate
        for (key_index = 0; key_index < 15; key_index = key_index + 1) begin : gen_flatten_keys
            assign round_keys_flat[1919-(128*key_index) -: 128] = round_keys[key_index];
        end
    endgenerate

    always @(posedge clk) begin
        if (reset) begin
            key_half_a <= 128'b0;
            key_half_b <= 128'b0;
            phase_g    <= 1'b1;
            next_round <= 4'd2;
            rcon       <= 8'h01;
            key_busy   <= 1'b0;
            key_ready  <= 1'b0;
        end
        else if (key_load) begin
            // The original 256-bit key is already RK0 followed by RK1.
            round_keys[0] <= key_in[255:128];
            round_keys[1] <= key_in[127:0];
            key_half_a    <= key_in[255:128];
            key_half_b    <= key_in[127:0];
            phase_g       <= 1'b1;
            next_round    <= 4'd2;
            rcon          <= 8'h01;
            key_busy      <= 1'b1;
            key_ready     <= 1'b0;
        end
        else if (key_busy) begin
            round_keys[next_round] <= expanded_half;

            if (phase_g) begin
                key_half_a <= expanded_half;

                if (next_round == 4'd14) begin
                    // RK14 is the last key required by AES-256.
                    key_busy  <= 1'b0;
                    key_ready <= 1'b1;
                end
                else begin
                    phase_g    <= 1'b0;
                    next_round <= next_round + 1'b1;
                end
            end
            else begin
                key_half_b <= expanded_half;
                phase_g    <= 1'b1;
                next_round <= next_round + 1'b1;
                rcon       <= next_rcon;
            end
        end
    end

endmodule

`default_nettype wire
