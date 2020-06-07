module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
	 input logic  clk, reset_n, start,
	 input logic  [15:0] message_addr, output_addr,
	 output logic done, mem_clk, mem_we,
	 output logic [15:0] mem_addr,
	 output logic [31:0] mem_write_data,
	 input logic [31:0] mem_read_data);
	
	// FSM state variables 
	enum logic [8:0] {IDLE, READ0, READ1, READ2, READ3, READ4, READ5, READ6, READ7, READ8, READ9, 
							READ10, READ11, READ12, READ13, READ14, READ15, READ16, READ17, READ18, READ19, 
							READ20, READ21, READ22, READ23, READ24, READ25,	READ26, READ27, READ28, READ29, READ30, READ31,
							OP1_1, OP1_2, OP1_3, OP1_4, OP1_5, OP1_6, OP1_7, OP1_8, OP1_9, OP1_10, OP1_11, OP1_12, OP1_13,
							OP1_14, OP1_15, OP1_16, OP1_17, OP1_18, OP1_19, OP1_20, OP1_21, OP1_22, OP1_23, OP1_24, OP1_25, 
							OP1_26, OP1_27, OP1_28, OP1_29, OP1_30, OP1_31, OP1_32, OP1_33, OP1_34, OP1_35, OP1_36, OP1_37, 
							OP1_38, OP1_39, OP1_40, OP1_41, OP1_42, OP1_43, OP1_44, OP1_45, OP1_46, OP1_47, OP1_48, OP1_49, 
							OP1_50, OP1_51, OP1_52, OP1_53, OP1_54, OP1_55, OP1_56, OP1_57, OP1_58, OP1_59, OP1_60, OP1_61, 
							OP1_62, OP1_63, OP1_64, OP1_65, OP1_66, OP1_67, OP1_68, OP1_69, OP1_70, OP1_71, OP1_72, OP1_73, 
							OP1_74, OP1_75, OP1_76, OP1_77, OP1_78, OP1_79, OP1_80, OP1_81, OP1_82, OP1_83, OP1_84, OP1_85,
							OP1_86, OP1_87, OP1_88, OP1_89, OP1_90, OP1_91, OP1_92, OP1_93, OP1_94, OP1_95, OP1_96, OP1_97,	OP1_98,
							INTER1, INTER2, INTER3, INTER4,
							OP2_1, OP2_2, OP2_3, OP2_4, OP2_5, OP2_6, OP2_7, OP2_8, OP2_9, OP2_10, OP2_11, OP2_12, OP2_13,
							OP2_14, OP2_15, OP2_16, OP2_17, OP2_18, OP2_19, OP2_20, OP2_21, OP2_22, OP2_23, OP2_24, OP2_25, 
							OP2_26, OP2_27, OP2_28, OP2_29, OP2_30, OP2_31, OP2_32, OP2_33, OP2_34, OP2_35, OP2_36, OP2_37, 
							OP2_38, OP2_39, OP2_40, OP2_41, OP2_42, OP2_43, OP2_44, OP2_45, OP2_46, OP2_47, OP2_48, OP2_49, 
							OP2_50, OP2_51, OP2_52, OP2_53, OP2_54, OP2_55, OP2_56, OP2_57, OP2_58, OP2_59, OP2_60, OP2_61, 
							OP2_62, OP2_63, OP2_64, OP2_65, OP2_66, OP2_67, OP2_68, OP2_69, OP2_70, OP2_71, OP2_72, OP2_73, 
							OP2_74, OP2_75, OP2_76, OP2_77, OP2_78, OP2_79, OP2_80, OP2_81, OP2_82, OP2_83, OP2_84, OP2_85,
							OP2_86, OP2_87, OP2_88, OP2_89, OP2_90, OP2_91, OP2_92, OP2_93, OP2_94, OP2_95, OP2_96, OP2_97, 
							OP2_98, OP2_99, OP2_100, OP2_101, OP2_102, OP2_103, OP2_104, OP2_105, OP2_106, OP2_107, OP2_108, 
							OP2_109, OP2_110, OP2_111, OP2_112, OP2_113, OP2_114, OP2_115, OP2_116, OP2_117, OP2_118, OP2_119, 
							OP2_120, OP2_121, OP2_122, OP2_123, OP2_124, OP2_125, OP2_126, OP2_127, OP2_128,
							WRITE0, WRITE1, WRITE2, WRITE3, WRITE4, WRITE5, WRITE6, WRITE7} state;
	
	// Local variables
	logic [31:0] w1[16], w2[4];
	logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
	logic [31:0] a, b, c, d, e, f, g, h; 
	logic [31:0] p;
	logic [ 5:0] i, j, t;
	logic [31:0] num_blocks;
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
	
	
	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, p);
		logic [31:0] A1, A0, ch, maj, t1, t2;
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
	
	function logic [31:0] wtnew(); // function with no inputs 
		logic [31:0] s0, s1;
		s0 = rightrotate(w1[1], 7) ^ rightrotate(w1[1], 18) ^ (w1[1] >> 3); 
		s1 = rightrotate(w1[14], 17) ^ rightrotate(w1[14], 19) ^ (w1[14] >> 10); 
		wtnew = w1[0] + s0 + w1[9] + s1; 
	endfunction
	
	function logic [31:0] rightrotate(input logic [31:0] x, input logic [ 7:0] r);
		begin
			rightrotate = ((x>>r) | (x<<(32-r)));
		end
	endfunction
	
	assign mem_clk = clk;
	assign mem_addr = cur_addr;
	assign mem_we = cur_we;
	assign mem_write_data = cur_write_data;

	always_ff @(posedge clk, negedge reset_n)
		begin
			if(!reset_n) 
				begin
					cur_we <= 1'b0;
					state <= IDLE;
				end 
			else 
				begin
					case (state)
						IDLE: 
							begin 
								if(start) 
									begin
										h0 <= 32'h6a09e667;
										h1 <= 32'hbb67ae85;
										h2 <= 32'h3c6ef372;
										h3 <= 32'ha54ff53a;
										h4 <= 32'h510e527f;
										h5 <= 32'h9b05688c;
										h6 <= 32'h1f83d9ab;
										h7 <= 32'h5be0cd19;
										
										a <= 32'h6a09e667;
										b <= 32'hbb67ae85;
										c <= 32'h3c6ef372;
										d <= 32'ha54ff53a;
										e <= 32'h510e527f;
										f <= 32'h9b05688c;
										g <= 32'h1f83d9ab;
										h <= 32'h5be0cd19;
										
										cur_we <= 1'b0;
										done <= 1'b0;
										cur_addr <= message_addr;
										state <= READ0;							
									end
								else
									begin
										state <= IDLE;
									end
							end
							
						READ0:
							begin
								state <= READ1;
							end
							
						READ1:
							begin
								w1[0] <= mem_read_data;
								cur_addr <= message_addr+16'd1;
								j <= 0;
								state <= READ2;
							end
							
						READ2:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ3;
							end
			
						READ3:
							begin
								w1[1] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 0
								cur_addr <= message_addr+16'd2;
								j <= j+6'd1;
								state <= READ4;
							end
							
						READ4:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ5;
							end
							
						READ5:
							begin
								w1[2] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 1
								cur_addr <= message_addr+16'd3;
								j <= j+6'd1;
								state <= READ6;
							end
						
						READ6:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ7;
							end
						
						READ7:
							begin
								w1[3] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 2
								cur_addr <= message_addr+16'd4;
								j <= j+6'd1;
								state <= READ8;
							end
							
						READ8:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ9;
							end
						
						READ9:
							begin
								w1[4] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 3
								cur_addr <= message_addr+16'd5;
								j <= j+6'd1;
								state <= READ10;
							end
							
						READ10:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ11;
							end
							
						READ11:
							begin
								w1[5] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 4
								cur_addr <= message_addr+16'd6;
								j <= j+6'd1;
								state <= READ12;
							end
							
						READ12:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ13;
							end
							
						READ13:
							begin
								w1[6] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 5
								cur_addr <= message_addr+16'd7;
								j <= j+6'd1;
								state <= READ14;
							end
							
						READ14:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ15;
							end
							
						READ15:
							begin
								w1[7] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 6
								cur_addr <= message_addr+16'd8;
								j <= j+6'd1;
								state <= READ16;
							end
							
						READ16:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ17;
							end
							
						READ17:
							begin
								w1[8] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 7
								cur_addr <= message_addr+16'd9;
								j <= j+6'd1;
								state <= READ18;
							end
							
						READ18:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ19;
							end
							
						READ19:
							begin
								w1[9] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 8
								cur_addr <= message_addr+16'd10;
								j <= j+6'd1;
								state <= READ20;
							end
							
						READ20:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ21;
							end
							
						READ21:
							begin
								w1[10] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 9
								cur_addr <= message_addr+16'd11;
								j <= j+6'd1;
								state <= READ22;
							end
							
						READ22:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ23;
							end
							
						READ23:
							begin
								w1[11] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 10
								cur_addr <= message_addr+16'd12;
								j <= j+6'd1;
								state <= READ24;
							end
							
						READ24:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ25;
							end
							
						READ25:
							begin
								w1[12] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 11
								cur_addr <= message_addr+16'd13;
								j <= j+6'd1;
								state <= READ26;
							end
							
						READ26:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ27;
							end
							
						READ27:
							begin
								w1[13] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 12
								cur_addr <= message_addr+16'd14;
								j <= j+6'd1;
								state <= READ28;
							end
							
						READ28:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ29;
							end
							
						READ29:
							begin
								w1[14] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 13
								cur_addr <= message_addr+16'd15;
								j <= j+6'd1;
								state <= READ30;
							end
							
						READ30:
							begin
								p <= k[j] + w1[j] + h;
								state <= READ31;
							end
							
						READ31:
							begin
								w1[15] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 14
								cur_addr <= message_addr+16'd16;
								j <= j+6'd1;
								state <= OP1_1;
							end
							
						OP1_1:
							begin
								p <= k[j] + w1[j] + h;   
								state <= OP1_2;
							end
							
						OP1_2:
							begin
								w2[0] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 15
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								cur_addr <= message_addr+16'd17;
								j <= j+6'd1;
								state <= OP1_3;
							end
							
						OP1_3:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_4;
							end
							
						OP1_4:
							begin
								w2[1] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 16
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								cur_addr <= message_addr+16'd18;
								j <= j+6'd1;
								state <= OP1_5;
							end
							
						OP1_5:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_6;
							end
							
						OP1_6:
							begin
								w2[2] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 17
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								cur_addr <= message_addr+16'd19;
								j <= j+6'd1;
								state <= OP1_7;
							end
							
						OP1_7:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_8;
							end
							
						OP1_8:
							begin
								w2[3] <= mem_read_data;
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 18
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_9;
							end
							
						OP1_9:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_10;
							end
							
						OP1_10:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 19
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_11;
							end
							
						OP1_11:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_12;
							end
						
						OP1_12:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 20
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_13;
							end
							
						OP1_13:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_14;
							end
							
						OP1_14:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 21
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_15;
							end
							
						OP1_15:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_16;
							end
							
						OP1_16:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 22
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_17;
							end
							
						OP1_17:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_18;
							end
							
						OP1_18:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 23
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_19;
							end
							
						OP1_19:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_20;
							end
							
						OP1_20:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 24
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_21;
							end
							
						OP1_21:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_22;
							end
							
						OP1_22:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 25
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_23;
							end
							
						OP1_23:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_24;
							end
							
						OP1_24:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 26
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_25;
							end
							
						OP1_25:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_26;
							end
							
						OP1_26:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 27
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_27;
							end
							
						OP1_27:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_28;
							end
							
						OP1_28:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 28
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_29;
							end
						
						OP1_29:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_30;
							end
							
						OP1_30:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 29
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_31;
							end
							
						OP1_31:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_32;
							end
							
						OP1_32:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 30
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_33;
							end
							
						OP1_33:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_34;
							end
							
						OP1_34:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 31
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_35;
							end
							
						OP1_35:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_36;
							end
							
						OP1_36:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 32
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_37;
							end
							
						OP1_37:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_38;
							end
							
						OP1_38:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 33
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_39;
							end
							
						OP1_39:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_40;
							end
							
						OP1_40:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 34
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_41;
							end
							
						OP1_41:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_42;
							end
							
						OP1_42:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 35
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_43;
							end
							
						OP1_43:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_44;
							end
							
						OP1_44:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 36
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_45;
							end
							
						OP1_45:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_46;
							end
						
						OP1_46:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 37
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_47;
							end
							
						OP1_47:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_48;
							end
							
						OP1_48:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 38
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_49;
							end
							
						OP1_49:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_50;
							end
							
						OP1_50:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 39 
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_51;
							end
							
						OP1_51:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_52;
							end
							
						OP1_52:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 40
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_53;
							end
							
						OP1_53:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_54;
							end
							
						OP1_54:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 41
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_55;
							end
							
						OP1_55:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_56;
							end
							
						OP1_56:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 42
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_57;
							end
							
						OP1_57:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_58;
							end
							
						OP1_58:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 43
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_59;
							end
							
						OP1_59:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_60;
							end
							
						OP1_60:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 44
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_61;
							end
							
						OP1_61:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_62;
							end
							
						OP1_62:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 45
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_63;
							end
						
						OP1_63:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_64;
							end
							
						OP1_64:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 46
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_65;
							end
							
						OP1_65:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_66;
							end
							
						OP1_66:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 47
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_67;
							end
							
						OP1_67:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_68;
							end
							
						OP1_68:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 48
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_69;
							end
							
						OP1_69:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_70;
							end
							
						OP1_70:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 49
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_71;
							end
							
						OP1_71:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_72;
							end
							
						OP1_72:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 50
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_73;
							end
							
						OP1_73:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_74;
							end
							
						OP1_74:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 51
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_75;
							end
							
						OP1_75:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_76;
							end
							
						OP1_76:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 52
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_77;
							end
							
						OP1_77:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_78;
							end
							
						OP1_78:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 53
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_79;
							end
							
						OP1_79:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_80;
							end
						
						OP1_80:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 54
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_81;
							end
							
						OP1_81:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_82;
							end
							
						OP1_82:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 55
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_83;
							end
							
						OP1_83:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_84;
							end
							
						OP1_84:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 56
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_85;
							end
							
						OP1_85:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_86;
							end
							
						OP1_86:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 57
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_87;
							end
							
						OP1_87:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_88;
							end
							
						OP1_88:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 58
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_89;
							end
							
						OP1_89:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_90;
							end
							
						OP1_90:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 59
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_91;
							end
							
						OP1_91:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_92;
							end
							
						OP1_92:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 60
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_93;
							end
							
						OP1_93:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_94;
							end
							
						OP1_94:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 61
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_95;
							end
							
						OP1_95:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_96;
							end
							
						OP1_96:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 62
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP1_97;
							end
						
						OP1_97:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP1_98;
							end
							
						OP1_98:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 63
								state <= INTER1;
							end
						
						INTER1:
							begin
								$display("FIRST BLOCK - a to h: %x, %x, %x, %x, %x, %x, %x, %x\n", a, b, c, d, e, f, g, h);
								for (t=0; t<4; t++) w1[t] <= w2[t];
								w1[4] <= 32'h80000000;
								for (t=5; t<15; t++) w1[t] <= 32'h00000000;
								w1[15] <= 32'd640;
								state <= INTER2;
							end
						
						INTER2:
							begin
								h0 <= h0+a;
								h1 <= h1+b;
								h2 <= h2+c;
								h3 <= h3+d;
								h4 <= h4+e;
								h5 <= h5+f;
								h6 <= h6+g;
								h7 <= h7+h;
								state <= INTER3;
							end
						
						INTER3:
							begin
								a <= h0;
								b <= h1;
								c <= h2;
								d <= h3;
								e <= h4;
								f <= h5;
								g <= h6;
								h <= h7;
								j <= 0;
								state <= OP2_1;
							end
							
						OP2_1:
							begin
								$display("FIRST BLOCK - h0 to h7: %x, %x, %x, %x, %x, %x, %x, %x\n", a, b, c, d, e, f, g, h);
								p <= k[j] + w1[j] + h;
								state <= OP2_2;
							end
						
						OP2_2:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 0
								j <= j+6'd1;
								state <= OP2_3;
							end
							
						OP2_3:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_4;
							end
							
						OP2_4:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 1
								j <= j+6'd1;
								state <= OP2_5;
							end
							
						OP2_5:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_6;
							end	
						
						OP2_6:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 2
								j <= j+6'd1;
								state <= OP2_7;
							end
							
						OP2_7:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_8;
							end
							
						OP2_8:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 3
								j <= j+6'd1;
								state <= OP2_9;
							end
							
						OP2_9:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_10;
							end
						
						OP2_10:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 4
								j <= j+6'd1;
								state <= OP2_11;
							end
							
						OP2_11:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_12;
							end
							
						OP2_12:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 5
								j <= j+6'd1;
								state <= OP2_13;
							end
							
						OP2_13:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_14;
							end
							
						OP2_14:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 6
								j <= j+6'd1;
								state <= OP2_15;
							end
							
						OP2_15:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_16;
							end
								
						OP2_16:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 7
								j <= j+6'd1;
								state <= OP2_17;
							end
							
						OP2_17:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_18;
							end
							
						OP2_18:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 8
								j <= j+6'd1;
								state <= OP2_19;
							end
							
						OP2_19:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_20;
							end
							
						OP2_20:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 9
								j <= j+6'd1;
								state <= OP2_21;
							end
							
						OP2_21:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_22;
							end
							
						OP2_22:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 10
								j <= j+6'd1;
								state <= OP2_23;
							end
						
						OP2_23:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_24;
							end
							
						OP2_24:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 11
								j <= j+6'd1;
								state <= OP2_25;
							end
							
						OP2_25:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_26;
							end
							
						OP2_26:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 12
								j <= j+6'd1;
								state <= OP2_27;
							end
							
						OP2_27:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_28;
							end
							
						OP2_28:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 13
								j <= j+6'd1;
								state <= OP2_29;
							end
							
						OP2_29:
							begin
								p <= k[j] + w1[j] + h;
								state <= OP2_30;
							end
							
						OP2_30:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 14
								j <= j+6'd1;
								state <= OP2_31;
							end
							
						OP2_31:
							begin
								p <= k[j] + w1[j] + h; 
								state <= OP2_32;
							end
							
						OP2_32:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 15
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_33;
							end
						
						OP2_33:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_34;
							end
							
						OP2_34:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 16
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_35;
							end
							
						OP2_35:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_36;
							end
							
						OP2_36:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 17
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_37;
							end
							
						OP2_37:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_38;
							end
							
						OP2_38:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 18
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_39;
							end
							
						OP2_39:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_40;
							end
							
						OP2_40:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 19
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_41;
							end
							
						OP2_41:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_42;
							end
						
						OP2_42:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 20
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_43;
							end
							
						OP2_43:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_44;
							end
							
						OP2_44:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 21
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_45;
							end
							
						OP2_45:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_46;
							end
							
						OP2_46:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 22
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_47;
							end
							
						OP2_47:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_48;
							end
							
						OP2_48:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 23
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_49;
							end
							
						OP2_49:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_50;
							end
							
						OP2_50:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 24
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_51;
							end
							
						OP2_51:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_52;
							end
							
						OP2_52:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 25
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_53;
							end
							
						OP2_53:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_54;
							end
							
						OP2_54:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 26
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_55;
							end
							
						OP2_55:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_56;
							end
							
						OP2_56:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 27
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_57;
							end
							
						OP2_57:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_58;
							end
							
						OP2_58:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 28
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_59;
							end
						
						OP2_59:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_60;
							end
							
						OP2_60:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 29
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_61;
							end
							
						OP2_61:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_62;
							end
							
						OP2_62:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 30
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_63;
							end
							
						OP2_63:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_64;
							end
							
						OP2_64:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 31
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_65;
							end
							
						OP2_65:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_66;
							end
							
						OP2_66:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 32
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_67;
							end
						
						OP2_67:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_68;
							end
							
						OP2_68:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 33
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_69;
							end
							
						OP2_69:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_70;
							end
							
						OP2_70:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 34
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_71;
							end
							
						OP2_71:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_72;
							end
							
						OP2_72:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 35
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_73;
							end
							
						OP2_73:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_74;
							end
							
						OP2_74:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 36
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_75;
							end
							
						OP2_75:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_76;
							end
						
						OP2_76:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 37
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_77;
							end
							
						OP2_77:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_78;
							end
							
						OP2_78:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 38
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_79;
							end
							
						OP2_79:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_80;
							end
							
						OP2_80:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 39 
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_81;
							end
							
						OP2_81:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_82;
							end
							
						OP2_82:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 40
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_83;
							end
							
						OP2_83:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_84;
							end
							
						OP2_84:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 41
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_85;
							end
							
						OP2_85:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_86;
							end
							
						OP2_86:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 42
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_87;
							end
							
						OP2_87:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_88;
							end
							
						OP2_88:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 43
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_89;
							end
							
						OP2_89:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_90;
							end
							
						OP2_90:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 44
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_91;
							end
							
						OP2_91:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_92;
							end
							
						OP2_92:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 45
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_93;
							end
						
						OP2_93:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_94;
							end
							
						OP2_94:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 46
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_95;
							end
							
						OP2_95:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_96;
							end
							
						OP2_96:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 47
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_97;
							end
							
						OP2_97:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_98;
							end
							
						OP2_98:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 48
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_99;
							end
							
						OP2_99:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_100;
							end
							
						OP2_100:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 49
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_101;
							end
							
						OP2_101:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_102;
							end
							
						OP2_102:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 50
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_103;
							end
							
						OP2_103:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_104;
							end
							
						OP2_104:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 51
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_105;
							end
							
						OP2_105:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_106;
							end
							
						OP2_106:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 52
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_107;
							end
							
						OP2_107:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_108;
							end
							
						OP2_108:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 53
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_109;
							end
							
						OP2_109:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_110;
							end
						
						OP2_110:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 54
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_111;
							end
							
						OP2_111:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_112;
							end
							
						OP2_112:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 55
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_113;
							end
							
						OP2_113:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_114;
							end
							
						OP2_114:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 56
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_115;
							end
							
						OP2_115:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_116;
							end
							
						OP2_116:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 57
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_117;
							end
							
						OP2_117:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_118;
							end
							
						OP2_118:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 58
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_119;
							end
							
						OP2_119:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_120;
							end
							
						OP2_120:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 59
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_121;
							end
							
						OP2_121:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_122;
							end
							
						OP2_122:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 60
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_123;
							end
							
						OP2_123:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_124;
							end
							
						OP2_124:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 61
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_125;
							end
							
						OP2_125:
							begin
								p <= k[j] + w1[15] + h;
								state <= OP2_126;
							end
							
						OP2_126:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 62
								w1[15] <= wtnew();
								for (t=0; t<15; t++) w1[t] <= w1[t+1];
								j <= j+6'd1;
								state <= OP2_127;
							end
						
						OP2_127:
							begin 
								p <= k[j] + w1[15] + h;
								state <= OP2_128;
							end
							
						OP2_128:
							begin
								{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, p); //Compression 63
								state <= INTER4;
							end
								
						INTER4:
							begin
								$display("SECOND BLOCK - a to h: %x, %x, %x, %x, %x, %x, %x, %x\n", a, b, c, d, e, f, g, h);
								
								h0 <= h0+a;
								h1 <= h1+b;
								h2 <= h2+c;
								h3 <= h3+d;
								h4 <= h4+e;
								h5 <= h5+f;
								h6 <= h6+g;
								h7 <= h7+h;
								state <= WRITE0;
							end
							
						WRITE0:
							begin
								$display("SECOND BLOCK - h0 to h7: %x, %x, %x, %x, %x, %x, %x, %x\n", h0, h1, h2, h3, h4, h5, h6, h7);
								cur_we <= 1'b1;
								cur_addr <= output_addr;
								cur_write_data <= h0;
								state <= WRITE1;
							end
							
						WRITE1:
							begin
								cur_addr <= output_addr+16'd1;
								cur_write_data <= h1;
								state <= WRITE2;
							end
							
						WRITE2:
							begin
								cur_addr <= output_addr+16'd2;
								cur_write_data <= h2;
								state <= WRITE3;
							end
							
						WRITE3:
							begin
								cur_addr <= output_addr+16'd3;
								cur_write_data <= h3;
								state <= WRITE4;
							end
							
						WRITE4:
							begin
								cur_addr <= output_addr+16'd4;
								cur_write_data <= h4;
								state <= WRITE5;
							end
							
						WRITE5:
							begin
								cur_addr <= output_addr+16'd5;
								cur_write_data <= h5;
								state <= WRITE6;
							end
							
						WRITE6:
							begin
								cur_addr <= output_addr+16'd6;
								cur_write_data <= h6;
								state <= WRITE7;
							end
							
						WRITE7:
							begin
								cur_addr <= output_addr+16'd7;
								cur_write_data <= h7;
								#20;
								done<=1'b1;
								state <= IDLE;
							end
						
						default: state <= IDLE;
							
					endcase
				end
		end

endmodule: simplified_sha256
