module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
	input logic  clk, reset_n, start,
	input logic  [15:0] message_addr, output_addr,
	output logic done, mem_clk, mem_we,
	output logic [15:0] mem_addr,
	output logic [31:0] mem_write_data,
	input logic [31:0] mem_read_data);

// FSM state variables 
	enum logic [2:0] {IDLE, INTER1, READ, BLOCK, INTER2, INTER3, COMPUTE, WRITE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
	logic [31:0] w1[32];
	logic [31:0] hash[8];
	logic [31:0] a, b, c, d, e, f, g, h;
	logic [31:0] p;
	logic [ 6:0] t, comp, offset;
	int i, blocks;
	logic        cur_we;
	logic [15:0] cur_addr;
	logic [31:0] cur_write_data;

// SHA256 K constants
	parameter int k[0:63] = '{
		32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
		32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
		32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
		32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
		32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
		32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
		32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
		32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
	};


// SHA256 hash round
	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, p);
		logic [31:0] A1, A0, ch, maj, t1, t2; // internal signals
		begin
			A1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
			ch = (e & f) ^ ((~e) & g);
			t1 = A1 + ch + p;
			A0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
			maj = (a & b) ^ (a & c) ^ (b & c);
			t2 = A0 + maj;
			sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
		end
	endfunction

	function logic [31:0] determine_num_blocks(input logic [31:0] size);
		logic[31:0] mod, quotient, block;
		begin
			quotient = (size*32)/512;
			mod = (size*32)%512;
			if(mod) block = quotient+1;
			else block = quotient;
			determine_num_blocks = block;
		end
	endfunction
	
	assign blocks = determine_num_blocks(NUM_OF_WORDS);
	
	function logic [31:0] wtnew();
		logic [31:0] s0, s1;
		begin
			s0 = rightrotate(w1[1], 7) ^ rightrotate(w1[1], 18) ^ (w1[1] >> 3);
			s1 = rightrotate(w1[14], 17) ^ rightrotate(w1[14], 19) ^ (w1[14] >> 10);
			wtnew = w1[0] + s0 + w1[9] + s1;
		end
	endfunction	
// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
	assign mem_clk = clk;
	assign mem_addr = cur_addr + offset;
	assign mem_we = cur_we;
	assign mem_write_data = cur_write_data;

	function logic [31:0] rightrotate(input logic [31:0] x, input logic [ 7:0] r);
		begin
			rightrotate = (x >> r) | (x << (32-r));
		end
	endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
	always_ff @(posedge clk, negedge reset_n)
		begin
			if(!reset_n) 
				begin
					cur_we <= 1'b0;
					state <= IDLE;
				end 
			else 
				case (state)
// Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
					IDLE: 
						begin
							if(start) 
								begin
									hash[0] <= 32'h6a09e667;
									hash[1] <= 32'hbb67ae85;
									hash[2] <= 32'h3c6ef372;
									hash[3] <= 32'ha54ff53a;
									hash[4] <= 32'h510e527f;
									hash[5] <= 32'h9b05688c;
									hash[6] <= 32'h1f83d9ab;
									hash[7] <= 32'h5be0cd19; 

									a <= 32'h6a09e667;
									b <= 32'hbb67ae85;
									c <= 32'h3c6ef372;
									d <= 32'ha54ff53a;
									e <= 32'h510e527f;
									f <= 32'h9b05688c;
									g <= 32'h1f83d9ab;
									h <= 32'h5be0cd19;

									i <= 7'd0;
									done <= 1'b0;
									comp <= 7'd0;
									cur_addr <= message_addr;
									cur_we <= 1'b0;
									offset <= 5'b0;
									state <= INTER1;
								end
						end

					INTER1:
						begin
							state <= READ;
						end 

					READ: 
						begin
							if(offset < NUM_OF_WORDS)
								begin
									w1[offset] <= mem_read_data;
									offset <= offset + 7'd1;
									state <= INTER1;
								end
							else 
								begin		
									w1[20] <= 32'h80000000;
									w1[31] <= 32'd640;
									for(t=21; t<31; t++) w1[t] <= 32'h0;
									offset <= 7'd0;
									state <= BLOCK;	
								end
						end				
// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
// and write back hash value back to memory
					BLOCK: 
						begin
							if(i < blocks) 
								begin
									i <= i + 7'd1;
									state <= INTER2;
								end
							else 
								begin
									cur_we <= 1;
									cur_addr <= output_addr;
									cur_write_data <= hash[0];
									state <= WRITE;
								end
						end

					INTER2: 
						begin
							p <= w1[0] + k[0] + h;
							for(t=0; t<15; t++) w1[t] <= w1[t+1];
							w1[15] <= wtnew();
							state <= INTER3;
						end

					INTER3: 
						begin
							{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p);
							p <= w1[0] + k[1] + g;
							for(t=0; t<15; t++) w1[t] <= w1[t+1];
							w1[15] <= wtnew();
							comp <= comp + 7'd1;
							state <= COMPUTE;
						end


					COMPUTE: 
						begin
							if(comp < 64) 
								begin
									p <= w1[0] + k[comp+1] + g;
									{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p);
									for(t=0; t<15; t++) w1[t] <= w1[t+1];
									w1[15] <= wtnew();
									comp <= comp + 7'd1;
									state <= COMPUTE;
								end
							else 
								begin
									for(t=0; t<16; t++) w1[t] <= w1[t+16];
									hash[0] <= hash[0]+a;
									hash[1] <= hash[1]+b;
									hash[2] <= hash[2]+c;
									hash[3] <= hash[3]+d;
									hash[4] <= hash[4]+e;
									hash[5] <= hash[5]+f;
									hash[6] <= hash[6]+g;
									hash[7] <= hash[7]+h;
									
									a <= hash[0]+a;
									b <= hash[1]+b;
									c <= hash[2]+c;
									d <= hash[3]+d;
									e <= hash[4]+e;
									f <= hash[5]+f;
									g <= hash[6]+g;
									h <= hash[7]+h;
									comp <= 7'd0;
									state <= BLOCK;
								end
						end

// h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
// h0 to h7 after compute stage has final computed hash value
// write back these h0 to h7 to memory starting from output_addr
					WRITE: 
						begin
							if(offset < 8)
								begin
									cur_write_data <= hash[offset+7'd1];
									offset <= offset + 7'd1;
									state <= WRITE;
								end
							else 
								begin
									done <= 1'b1;
									state <= IDLE;
								end
						end
				endcase
			end
// Generate done when SHA256 hash computation has finished and moved to IDLE state
//	assign done = (state == IDLE);

endmodule: simplified_sha256