`timescale 1ns / 1ps
`default_nettype none

module tb_aes256_pipeline;

    reg          clk;
    reg          reset;
    reg          key_load;
    reg  [255:0] key_in;
    wire         key_busy;
    wire         key_ready;

    reg  [127:0] data_in;
    reg          input_valid;
    wire         input_ready;

    wire [127:0] data_out;
    wire         output_valid;

    aes256_pipeline dut (
        .clk          (clk),
        .reset        (reset),
        .key_load     (key_load),
        .key_in       (key_in),
        .key_busy     (key_busy),
        .key_ready    (key_ready),
        .data_in      (data_in),
        .input_valid  (input_valid),
        .input_ready  (input_ready),
        .data_out     (data_out),
        .output_valid (output_valid)
    );

    initial clk = 1'b0;
    always #5 clk = ~clk;

    reg [127:0] expected_ciphertext [0:15];
    integer write_index;
    integer read_index;
    integer errors;
    integer key_wait_cycles;

    task load_aes256_key;
        input [255:0] new_key;
        begin
            @(negedge clk);
            key_in   = new_key;
            key_load = 1'b1;

            @(negedge clk);
            key_load = 1'b0;

            key_wait_cycles = 0;
            while (key_ready !== 1'b1) begin
                @(negedge clk);
                key_wait_cycles = key_wait_cycles + 1;
                if (key_wait_cycles > 20) begin
                    $display("FAIL: key expansion timeout");
                    $finish;
                end
            end

            $display("Key expansion complete after %0d observed wait clocks", key_wait_cycles);
        end
    endtask

    task send_block;
        input [127:0] plaintext;
        input [127:0] expected;
        begin
            @(negedge clk);
            while (input_ready !== 1'b1)
                @(negedge clk);

            data_in    = plaintext;
            input_valid = 1'b1;
            expected_ciphertext[write_index] = expected;
            write_index = write_index + 1;
        end
    endtask

    // Check results after each rising-edge update has settled.
    always @(negedge clk) begin
        if (output_valid) begin
            if (read_index >= write_index) begin
                $display("FAIL: unexpected output %032h", data_out);
                errors = errors + 1;
            end
            else if (data_out !== expected_ciphertext[read_index]) begin
                $display("FAIL block %0d", read_index);
                $display("  expected = %032h", expected_ciphertext[read_index]);
                $display("  obtained = %032h", data_out);
                errors = errors + 1;
            end
            else begin
                $display("PASS block %0d: %032h", read_index, data_out);
            end
            read_index = read_index + 1;
        end
    end

    initial begin
        reset       = 1'b1;
        key_load    = 1'b0;
        key_in      = 256'b0;
        data_in     = 128'b0;
        input_valid = 1'b0;
        write_index = 0;
        read_index  = 0;
        errors      = 0;

        repeat (4) @(posedge clk);
        @(negedge clk);
        reset = 1'b0;

        // FIPS 197, AES-256 cipher example.
        load_aes256_key(
            256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        );

        send_block(
            128'h00112233445566778899aabbccddeeff,
            128'h8ea2b7ca516745bfeafc49904b496089
        );

        @(negedge clk);
        input_valid = 1'b0;

        wait (read_index == write_index);

        // NIST SP 800-38A AES-256 ECB vectors. Four blocks are deliberately
        // supplied on consecutive clocks to verify initiation interval = 1.
        load_aes256_key(
            256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
        );

        send_block(
            128'h6bc1bee22e409f96e93d7e117393172a,
            128'hf3eed1bdb5d2a03c064b5a7e3db181f8
        );
        send_block(
            128'hae2d8a571e03ac9c9eb76fac45af8e51,
            128'h591ccb10d410ed26dc5ba74a31362870
        );
        send_block(
            128'h30c81c46a35ce411e5fbc1191a0a52ef,
            128'hb6ed21b99ca6f4f9f153e7b1beafed1d
        );
        send_block(
            128'hf69f2445df4f9b17ad2b417be66c3710,
            128'h23304b7a39f9f3ff067d8d8f9e24ecc7
        );

        @(negedge clk);
        input_valid = 1'b0;

        wait (read_index == write_index);
        repeat (2) @(negedge clk);

        if (errors == 0)
            $display("ALL TESTS PASSED (%0d blocks)", read_index);
        else
            $display("TEST FAILED: %0d error(s)", errors);

        $finish;
    end

    initial begin
        // Independent safety timeout.
        #5000;
        $display("FAIL: global simulation timeout");
        $finish;
    end

endmodule

`default_nettype wire
