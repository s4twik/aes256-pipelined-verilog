`timescale 1ns / 1ps
`default_nettype none

// Apply the AES forward S-box independently to all 16 state bytes.
// Byte 0 occupies state_in[127:120]; byte 15 occupies state_in[7:0].
module aes_sub_bytes (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);

    genvar byte_index;
    generate
        for (byte_index = 0; byte_index < 16; byte_index = byte_index + 1) begin : gen_sbox
            aes_sbox u_sbox (
                .data_in  (state_in [127-(8*byte_index) -: 8]),
                .data_out (state_out[127-(8*byte_index) -: 8])
            );
        end
    endgenerate

endmodule

`default_nettype wire
