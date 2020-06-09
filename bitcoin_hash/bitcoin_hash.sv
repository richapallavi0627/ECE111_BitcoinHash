module bitcoin_hash(input  logic clk, reset_n, start,
					input  logic [15:0] message_addr, output_addr,
					output logic done,
					output logic mem_clk, mem_we,
					output logic [15:0] mem_addr,
					output logic [31:0] mem_write_data,
					input  logic [31:0] mem_read_data);

enum logic [3:0] {IDLE=4'b0000, READ1=4'b0001, READ2=4'b0010, PRECOMPUTE=4'b0110, STORE=4'b0011, COMPUTE=4'b101, STORE0=4'b111, STORE2=4'b100, WRITE=4'b1111} state;

assign mem_clk = clk;

parameter NUM_NONCES = 16;

logic [31:0] p; // stores h+k+w 

parameter int nonce[0:15] = '{
   32'd0,32'd1,32'd2,32'd3,32'd4,32'd5,32'd6,32'd7,
   32'd8,32'd9,32'd10,32'd11,32'd12,32'd13,32'd14,32'd15
};

logic [31:0] hash[16];
logic [15:0] count_addr;
logic [15:0] write_count_addr;
logic [6:0] cnt;
logic [1:0] compute_iter;


genvar q;
	generate
		for (q=0; q<NUM_NONCES; q++) begin : generate_sha256_modules
			sha256 sha256_inst (
				.clk(clk),
				.reset_n(reset_n),
				.state(state),
				.start(start),
				._nonce(nonce[q]),
				.mem_read_data(mem_read_data),
				.hh(hash[q]));
		end
endgenerate

always@(posedge clk, negedge reset_n)
begin
	if(!reset_n) begin
		done <= 0;
		count_addr <= 0;
		write_count_addr<=0;
		state <= IDLE;
	end else begin

	case(state)
		IDLE: begin
			if(start) begin
				compute_iter <= 0;
				mem_we <= 0;
				mem_addr <= message_addr + count_addr;
				count_addr <= count_addr + 1;	
				state <= READ1;
			end
		end
			
		READ1: begin
			cnt <= 0;
			mem_addr <= message_addr + count_addr;
			count_addr <= count_addr + 1;		
			state <= READ2;
		end
				
		READ2: begin
			mem_addr <= message_addr + count_addr;
			count_addr <= count_addr + 1;
			state <= PRECOMPUTE;
		end
				
		PRECOMPUTE: begin
			mem_addr <= message_addr + count_addr;
			count_addr <= count_addr + 1;
			cnt <= 1;

			if(compute_iter == 1) begin
				state <= STORE;
			end else begin
				state <= STORE0;
			end
		end
			
		STORE0: begin
			if (cnt < 15) begin
				mem_addr <= message_addr + count_addr;
				count_addr <= count_addr + 1;
			end

			cnt <= cnt + 1;
							
			if(cnt == 64) begin
				compute_iter <= compute_iter + 1;
				state<=COMPUTE;
			end else begin
				state<=STORE0;
			end
		end	
			
		STORE: begin
			if (cnt < 2) begin
				mem_addr <= message_addr + count_addr;
				count_addr <= count_addr + 1;
			end

			cnt <= cnt + 1;
							
			if(cnt == 64) begin
				compute_iter <= compute_iter + 1;
				state<=COMPUTE;
			end else begin
				state<=STORE;
			end
		end	

		STORE2: begin
			cnt <= cnt + 1;
					
			if(cnt == 64) begin
				compute_iter <= compute_iter + 1;
				mem_addr <= message_addr + 16;
				count_addr <= 17;
				state<=COMPUTE;
			end else begin
				state<=STORE2;
			end
		end
			
		COMPUTE: begin			
			if(compute_iter == 1) begin
				mem_addr <= message_addr + 16;
				count_addr <= 17;
				state<=READ1;
				
			end else if(compute_iter==2) begin
				cnt <= 1;
				state <= STORE2;
				
			end else if(compute_iter==3) begin
				cnt <= 0;
				state <= WRITE;
			end	
		end
		
		WRITE: begin
			mem_we <= 1;
			mem_addr <= output_addr + write_count_addr;
			mem_write_data <= hash[cnt];
			cnt <= cnt + 1;
			write_count_addr <= write_count_addr + 1;
			if(write_count_addr == 16) begin
				done<=1;
			end else begin
				state<= WRITE;
			end
		end
	endcase
	end
end
endmodule


// SHA256_MODULE

module sha256   (input  logic clk, 
				 input  logic reset_n,
				 input  logic [3:0] state,
				 input  logic start,
				 input  logic [31:0] _nonce,
				 input  logic [31:0] mem_read_data,
				 output logic [31:0] hh);

parameter int IDLE = 4'b0000;
parameter int READ1 = 4'b0001;
parameter int READ2 = 4'b0010;
parameter int PRECOMPUTE = 4'b0110;
parameter int STORE = 4'b0011;
parameter int COMPUTE = 4'b0101;
parameter int STORE0 = 4'b0111;
parameter int STORE2 = 4'b0100;
parameter int WRITE = 4'b1111;


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

// SHA256 hash round -- precomputing "h+k+w = p"
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, p);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = S1 + ch + p;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;

    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// right rotation
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [7:0] r);
begin
    rightrotate = (x >> r) | (x << (32-r));
end
endfunction

logic [31:0] w[16];
logic [31:0] p;
int t;

//function to compute new Wt
function logic [31:0] wtnew(); 
	logic [31:0] s0, s1;
	s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3); 
	s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10); 
	wtnew = w[0] + s0 + w[9] + s1; 
endfunction

logic [6:0] cnt;
logic [31:0] fh[8];
logic [31:0] A,B,C,D,E,F,G,H;
logic [1:0] compute_iter;

always@(posedge clk, negedge reset_n)
begin
	if(!reset_n) begin
			
	end else begin
	case(state)
		IDLE: begin
			if(start) begin
				A <= 32'h6a09e667;
				B <= 32'hbb67ae85;
				C <= 32'h3c6ef372;
				D <= 32'ha54ff53a;
				E <= 32'h510e527f;
				F <= 32'h9b05688c;
				G <= 32'h1f83d9ab;
				H <= 32'h5be0cd19;

				fh[0] <= 32'h6a09e667;
				fh[1] <= 32'hbb67ae85;
				fh[2] <= 32'h3c6ef372;
				fh[3] <= 32'ha54ff53a;
				fh[4] <= 32'h510e527f;
				fh[5] <= 32'h9b05688c;
				fh[6] <= 32'h1f83d9ab;
				fh[7] <= 32'h5be0cd19;	
				
				compute_iter <= 0;
			end
		end
			
		READ1: begin
			cnt <= 0;
		end
				
		READ2: begin
			w[15] <= mem_read_data;
		end
				
		PRECOMPUTE: begin	
			p <= k[cnt] + fh[7] + w[15];
			w[15] <= mem_read_data;
				
			for (t=0; t<15; t++) w[t] <= w[t+1];
				
			cnt <= 1;
		end
			
		STORE0: begin
			if (cnt < 15) begin
				w[15]<=mem_read_data;
			end else begin
				w[15] <= wtnew();
			end
				
			for (t=0; t<15; t++) w[t] <= w[t+1];
			p <= k[cnt] + G + w[15];
			{A, B, C, D, E, F, G, H} <= sha256_op(A, B, C, D, E, F, G, p);
				
			cnt <= cnt + 1;
							
			if(cnt == 64) begin
				compute_iter <= compute_iter + 1;
			end
		end	
			
		STORE: begin
			if (cnt < 2) begin
				w[15]<=mem_read_data;
			end else if (cnt == 2) begin
				w[15]<=_nonce;
			end else if (cnt == 3) begin
				w[15]<=32'h80000000;
			end else if (cnt < 14) begin
				w[15]<=32'h00000000;
			end else if (cnt == 14) begin
				w[15]<=32'd640;
			end else begin
				w[15] <= wtnew();
			end
			
			for (t=0; t<15; t++) w[t] <= w[t+1];

			p <= k[cnt] + G + w[15];
			{A, B, C, D, E, F, G, H} <= sha256_op(A, B, C, D, E, F, G, p);
				
			cnt <= cnt + 1;
							
			if(cnt == 64) begin
				compute_iter <= compute_iter + 1;
			end
		end	

		STORE2: begin
			//padding 1, length and 0's
			if (cnt < 7) begin
				w[15]<=fh[cnt+1];
			end else if (cnt == 7) begin
				w[15]<=32'h80000000;
			end else if (cnt < 14) begin
				w[15]<=32'h00000000;
			end else if (cnt == 14) begin
				w[15]<=32'd256;
			end else begin
				w[15] <= wtnew();
			end
				
			for (t=0; t<15; t++) w[t] <= w[t+1];

			p <= k[cnt] + G + w[15];
			{A, B, C, D, E, F, G, H} <= sha256_op(A, B, C, D, E, F, G, p);
				
			cnt <= cnt + 1;
					
			if(cnt == 64) begin
				compute_iter <= compute_iter + 1;
				fh[0] <= 32'h6a09e667;
				fh[1] <= 32'hbb67ae85;
				fh[2] <= 32'h3c6ef372;
				fh[3] <= 32'ha54ff53a;
				fh[4] <= 32'h510e527f;
				fh[5] <= 32'h9b05688c;
				fh[6] <= 32'h1f83d9ab;
				fh[7] <= 32'h5be0cd19;
			end
		end
			
		COMPUTE: begin
			fh[0] <= fh[0] + A;
			fh[1] <= fh[1] + B;
			fh[2] <= fh[2] + C;
			fh[3] <= fh[3] + D;
			fh[4] <= fh[4] + E;
			fh[5] <= fh[5] + F;
			fh[6] <= fh[6] + G;
			fh[7] <= fh[7] + H;

			A <= fh[0] + A;
			B <= fh[1] + B;
			C <= fh[2] + C;
			D <= fh[3] + D;
			E <= fh[4] + E;
			F <= fh[5] + F;
			G <= fh[6] + G;
			H <= fh[7] + H;
			
			if(compute_iter==2) begin
				A <= 32'h6a09e667;
				B <= 32'hbb67ae85;
				C <= 32'h3c6ef372;
				D <= 32'ha54ff53a;
				E <= 32'h510e527f;
				F <= 32'h9b05688c;
				G <= 32'h1f83d9ab;
				H <= 32'h5be0cd19;
				cnt <= 1;
				w[14] <= fh[0] + A;
				w[15] <= fh[1] + B;
				p <= k[0] + 32'h5be0cd19 + fh[0] + A;
				
			end else if(compute_iter==3) begin
				hh<=fh[0] + A;
			end
		end
		
		WRITE: begin
		end

	endcase
	end
end
endmodule
