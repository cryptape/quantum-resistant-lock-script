#define state_ptr a0
#define state_buf a2

#define nrounds 24
#define sp_cache_buf_size -280 // sp 5 * 7 * 8
#define sp_round_constants -288 // keccakf_roundconstants
#define sp_loop_count_val -296 // round

#define round_constants_ptr sp_round_constants(sp)
#define loop_count_val sp_loop_count_val(sp)

#define aba 0(state_ptr)
#define abe 8(state_ptr)
#define abi 16(state_ptr)
#define abo 24(state_ptr)
#define abu 32(state_ptr)

#define aga 40(state_ptr)
#define age 48(state_ptr)
#define agi 56(state_ptr)
#define ago 64(state_ptr)
#define agu 72(state_ptr)

#define aka 80(state_ptr)
#define ake 88(state_ptr)
#define aki 96(state_ptr)
#define ako 104(state_ptr)
#define aku 112(state_ptr)

#define ama 120(state_ptr)
#define ame 128(state_ptr)
#define ami 136(state_ptr)
#define amo 144(state_ptr)
#define amu 152(state_ptr)

#define asa 160(state_ptr)
#define ase 168(state_ptr)
#define asi 176(state_ptr)
#define aso 184(state_ptr)
#define asu 192(state_ptr)

#define bca 0(state_buf)
#define bce 8(state_buf)
#define bci 16(state_buf)
#define bco 24(state_buf)
#define bcu 32(state_buf)

#define da 40(state_buf)
#define de 48(state_buf)
#define di 56(state_buf)
#define do 64(state_buf)
#define du 72(state_buf)

#define eba 80(state_buf)
#define ebe 88(state_buf)
#define ebi 96(state_buf)
#define ebo 104(state_buf)
#define ebu 112(state_buf)

#define ega 120(state_buf)
#define ege 128(state_buf)
#define egi 136(state_buf)
#define ego 144(state_buf)
#define egu 152(state_buf)

#define eka 160(state_buf)
#define eke 168(state_buf)
#define eki 176(state_buf)
#define eko 184(state_buf)
#define eku 192(state_buf)

#define ema 200(state_buf)
#define eme 208(state_buf)
#define emi 216(state_buf)
#define emo 224(state_buf)
#define emu 232(state_buf)

#define esa 240(state_buf)
#define ese 248(state_buf)
#define esi 256(state_buf)
#define eso 264(state_buf)
#define esu 272(state_buf)

# registers that can be used:
# ra
# t0 (todo)
# t1 ~ t6
# a0 ~ a7
# a0 state ptr
# a1 x keccakf_roundconstants
# a2 state_buf
# a3 x i (loop count))

# a1 bca
# a3 bce
# a4 bci
# a5 bco
# a6 bcu

# a7 da
# t4 de
# t5 di
# t6 do
# t0 du

.text
.globl riscv_keccak_f1600
.align 4
# a0 state ptr
# a1 keccakf_roundconstants
riscv_keccak_f1600:
addi state_buf,sp,sp_cache_buf_size # sp need offset 5 * 7 * 8
sd a1,round_constants_ptr

li t1,0
sd t1,loop_count_val
for_begin:
# bca = aba ^ aga ^ aka ^ ama ^ asa;
ld t1,aba
ld t2,aga
xor a1,t1,t2
ld t1,aka
ld t2,ama
xor a1,a1,t1
xor a1,a1,t2
ld t1,asa
xor a1,a1,t1
# sd a1,bca

# bce = abe ^ age ^ ake ^ ame ^ ase;
ld t1,abe
ld t2,age
xor a3,t1,t2
ld t1,ake
ld t2,ame
xor a3,a3,t1
xor a3,a3,t2
ld t1,ase
xor a3,a3,t1
# sd a3,bce

# bci = abi ^ agi ^ aki ^ ami ^ asi;
ld t1,abi
ld t2,agi
xor a4,t1,t2
ld t1,aki
ld t2,ami
xor a4,a4,t1
xor a4,a4,t2
ld t1,asi
xor a4,a4,t1
# sd a4,bci

# bco = abo ^ ago ^ ako ^ amo ^ aso;
ld t1,abo
ld t2,ago
xor a5,t1,t2
ld t1,ako
ld t2,amo
xor a5,a5,t1
xor a5,a5,t2
ld t1,aso
xor a5,a5,t1
# sd a5,bco

# bcu = abu ^ agu ^ aku ^ amu ^ asu;
ld t1,abu
ld t2,agu
xor a6,t1,t2
ld t1,aku
ld t2,amu
xor a6,a6,t1
xor a6,a6,t2
ld t1,asu
xor a6,a6,t1
# sd a6,bcu

li t1,1
# da = bcu ^ rol(bce,1);
# ld t2,bcu
# ld t3,bce
# rol t3,a3,t1
.byte 0x33,0x9e,0x66,0x60
xor a7,a6,t3
# sd a7,da

# de = bca ^ rol(bci,1);
# ld t2,bca
# ld t3,bci
# rol t3,a4,t1
.byte 0x33,0x1e,0x67,0x60
xor t4,a1,t3
# sd t4,de

# di = bce ^ rol(bco,1);
# ld t2,bce
# ld t3,bco
# rol t3,a5,t1
.byte 0x33,0x9e,0x67,0x60
xor t5,a3,t3
# sd t5,di

# do = bci ^ rol(bcu,1);
# ld t2,bci
# ld t3,bcu
# rol t3,a6,t1
.byte 0x33,0x1e,0x68,0x60
xor t6,a4,t3
# sd t6,do

# du = bco ^ rol(bca,1);
# ld t2,bco
# ld t3,bca
# rol t3,a1,t1
.byte 0x33,0x9e,0x65,0x60
xor t0,a5,t3
# sd t0,du

# aba ^= da;
ld t1,aba
# ld t2,da
xor a1,t1,a7
sd a1,aba

# bca = aba;
# sd a1,bca

# age ^= de;
ld t1,age
# ld t2,de
xor t1,t1,t4
sd t1,age

# bce = rol(age,44);
li t1,44
ld t2,age
# rol a3,t2,t1
.byte 0xb3,0x96,0x63,0x60
# sd a3,bce

# aki ^= di;
ld t1,aki
# ld t2,di
xor t1,t1,t5
sd t1,aki

# bci = rol(aki,43);
li t1,43
ld t2,aki
# rol a4,t2,t1
.byte 0x33,0x97,0x63,0x60
# sd a4,bci

# amo ^= do;
ld t1,amo
# ld t2,do
xor t1,t1,t6
sd t1,amo

# bco = rol(amo,21);
li t1,21
ld t2,amo
# rol a5,t2,t1
.byte 0xb3,0x97,0x63,0x60
# sd a5,bco

# asu ^= du;
ld t1,asu
# ld t2,du
xor t1,t1,t0
sd t1,asu

# bcu = rol(asu,14);
li t1,14
ld t2,asu
# rol a6,t2,t1
.byte 0x33,0x98,0x63,0x60
# sd a6,bcu

# eba = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
# sd t3,eba

# eba ^= keccakf_roundconstants[round];
ld t1,loop_count_val
slli t1,t1,3
ld t2,round_constants_ptr
add t1,t2,t1
ld t1,0(t1)
xor t3,t3,t1
sd t3,eba

# ebe = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,ebe

# ebi = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,ebi

# ebo = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,ebo

# ebu = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,ebu

# abo ^= do;
ld t1,abo
# ld t2,do
xor t1,t1,t6
sd t1,abo

# bca = rol(abo,28);
li t2,28
# rol a1,t1,t2
.byte 0xb3,0x15,0x73,0x60
# sd t2,bca

# agu ^= du;
ld t1,agu
# ld t2,du
xor t1,t1,t0
sd t1,agu

# bce = rol(agu,20);
li t2,20
# rol a3,t1,t2
.byte 0xb3,0x16,0x73,0x60
# sd a3,bce

# aka ^= da;
ld t1,aka
# ld t2,da
xor t1,t1,a7
sd t1,aka

# bci = rol(aka,3);
li t2,3
# rol a4,t1,t2
.byte 0x33,0x17,0x73,0x60
# sd a4,bci

# ame ^= de;
ld t1,ame
# ld t2,de
xor t1,t1,t4
sd t1,ame

# bco = rol(ame,45);
li t2,45
# rol a5,t1,t2
.byte 0xb3,0x17,0x73,0x60
# sd a5,bco

# asi ^= di;
ld t1,asi
# ld t2,di
xor t1,t1,t5
sd t1,asi

# bcu = rol(asi,61);
li t2,61
# rol a6,t1,t2
.byte 0x33,0x18,0x73,0x60
# sd a6,bcu

# ega = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
sd t3,ega

# ege = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,ege

# egi = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,egi

# ego = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,ego

# egu = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,egu

# abe ^= de;
# bca = rol(abe,1);
ld t1,abe
# ld t2,de
xor t1,t1,t4
sd t1,abe

li t2,1
# rol a1,t1,t2
.byte 0xb3,0x15,0x73,0x60
# sd a1,bca

# agi ^= di;
# bce = rol(agi,6);
ld t1,agi
# ld t2,di
xor t1,t1,t5
sd t1,agi

li t2,6
# rol a3,t1,t2
.byte 0xb3,0x16,0x73,0x60
# sd a3,bce

# ako ^= do;
# bci = rol(ako,25);
ld t1,ako
# ld t2,do
xor t1,t1,t6
sd t1,ako

li t2,25
# rol a4,t1,t2
.byte 0x33,0x17,0x73,0x60
# sd a4,bci

# amu ^= du;
# bco = rol(amu,8);
ld t1,amu
# ld t2,du
xor t1,t1,t0
sd t1,amu

li t2,8
# rol a5,t1,t2
.byte 0xb3,0x17,0x73,0x60
# sd a5,bco

# asa ^= da;
# bcu = rol(asa,18);
ld t1,asa
# ld t2,da
xor t1,t1,a7
sd t1,asa

li t2,18
# rol a6,t1,t2
.byte 0x33,0x18,0x73,0x60
# sd a6,bcu

# todo joii,need optimiaztion
# eka = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
sd t3,eka

# eke = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,eke

# eki = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,eki

# eko = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,eko

# eku = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,eku

# abu ^= du;
# bca = rol(abu,27);
ld t1,abu
# ld t2,du
xor t1,t1,t0
sd t1,abu

li t2,27
# rol a1,t1,t2
.byte 0xb3,0x15,0x73,0x60
# sd t2,bca

# aga ^= da;
# bce = rol(aga,36);
ld t1,aga
# ld t2,da
xor t1,t1,a7
sd t1,aga

li t2,36
# rol a3,t1,t2
.byte 0xb3,0x16,0x73,0x60
# sd a3,bce

# ake ^= de;
# bci = rol(ake,10);
ld t1,ake
# ld t2,de
xor t1,t1,t4
sd t1,ake

li t2,10
# rol a4,t1,t2
.byte 0x33,0x17,0x73,0x60
# sd a4,bci

# ami ^= di;
# bco = rol(ami,15);
ld t1,ami
# ld t2,di
xor t1,t1,t5
sd t1,ami

li t2,15
# rol a5,t1,t2
.byte 0xb3,0x17,0x73,0x60
# sd a5,bco

# aso ^= do;
# bcu = rol(aso,56);
ld t1,aso
# ld t2,do
xor t1,t1,t6
sd t1,aso

li t2,56
# rol a6,t1,t2
.byte 0x33,0x18,0x73,0x60
# sd a6,bcu

# ema = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
sd t3,ema

# eme = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,eme

# emi = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,emi

# emo = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,emo

# emu = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,emu

# abi ^= di;
# bca = rol(abi,62);
ld t1,abi
# ld t2,di
xor t1,t1,t5
sd t1,abi
li t2,62
# rol a1,t1,t2
.byte 0xb3,0x15,0x73,0x60
# sd a1,bca

# ago ^= do;
# bce = rol(ago,55);
ld t1,ago
# ld t2,do
xor t1,t1,t6
sd t1,ago
li t2,55
# rol a3,t1,t2
.byte 0xb3,0x16,0x73,0x60
# sd a3,bce

# aku ^= du;
# bci = rol(aku,39);
ld t1,aku
# ld t2,du
xor t1,t1,t0
sd t1,aku
li t2,39
# rol a4,t1,t2
.byte 0x33,0x17,0x73,0x60
# sd a4,bci

# ama ^= da;
# bco = rol(ama,41);
ld t1,ama
# ld t2,da
xor t1,t1,a7
sd t1,ama
li t2,41
# rol a5,t1,t2
.byte 0xb3,0x17,0x73,0x60
# sd a5,bco

# ase ^= de;
# bcu = rol(ase,2);
ld t1,ase
# ld t2,de
xor t1,t1,t4
sd t1,ase
li t2,2
# rol a6,t1,t2
.byte 0x33,0x18,0x73,0x60
# sd a6,bcu

# esa = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
sd t3,esa

# ese = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,ese

# esi = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,esi

# eso = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,eso

# esu = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,esu

# bca = eba ^ ega ^ eka ^ ema ^ esa;
ld t1,eba
ld t2,ega
xor a1,t1,t2
ld t1,eka
ld t2,ema
xor a1,a1,t1
xor a1,a1,t2
ld t1,esa
xor a1,a1,t1
# sd a1,bca

# bce = ebe ^ ege ^ eke ^ eme ^ ese;
ld t1,ebe
ld t2,ege
xor a3,t1,t2
ld t1,eke
ld t2,eme
xor a3,a3,t1
xor a3,a3,t2
ld t1,ese
xor a3,a3,t1
# sd a3,bce

# bci = ebi ^ egi ^ eki ^ emi ^ esi;
ld t1,ebi
ld t2,egi
xor a4,t1,t2
ld t1,eki
ld t2,emi
xor a4,a4,t1
xor a4,a4,t2
ld t1,esi
xor a4,a4,t1
# sd a4,bci

# bco = ebo ^ ego ^ eko ^ emo ^ eso;
ld t1,ebo
ld t2,ego
xor a5,t1,t2
ld t1,eko
ld t2,emo
xor a5,a5,t1
xor a5,a5,t2
ld t1,eso
xor a5,a5,t1
# sd a5,bco

# bcu = ebu ^ egu ^ eku ^ emu ^ esu;
ld t1,ebu
ld t2,egu
xor a6,t1,t2
ld t1,eku
ld t2,emu
xor a6,a6,t1
xor a6,a6,t2
ld t1,esu
xor a6,a6,t1
# sd a6,bcu

li t3,1

# da = bcu ^ rol(bce,1);
# ld t1,bcu
# ld t2,bce
# rol t2,a3,t3
.byte 0xb3,0x93,0xc6,0x61
xor a7,a6,t2
# sd a7,da

# de = bca ^ rol(bci,1);
# ld t1,bca
# ld t2,bci
# rol t2,a4,t3
.byte 0xb3,0x13,0xc7,0x61
xor t4,a1,t2
# sd t4,de

# di = bce ^ rol(bco,1);
# ld t1,bce
# ld t2,bco
# rol t2,a5,t3
.byte 0xb3,0x93,0xc7,0x61
xor t5,a3,t2
# sd t5,di

# do = bci ^ rol(bcu,1);
# ld t1,bci
# ld t2,bcu
# rol t2,a6,t3
.byte 0xb3,0x13,0xc8,0x61
xor t6,a4,t2
# sd t6,do

# du = bco ^ rol(bca,1);
# ld t1,bco
# ld t2,bca
# rol t2,a1,t3
.byte 0xb3,0x93,0xc5,0x61
xor t0,a5,t2
# sd t0,du

# eba ^= da;
# bca = eba;
ld t1,eba
# ld t2,da
xor a1,t1,a7
sd a1,eba
# sd a1,bca

# ege ^= de;
# bce = rol(ege,44);
ld t1,ege
# ld t2,de
li t3,44
xor t1,t1,t4
# rol a3,t1,t3
.byte 0xb3,0x16,0xc3,0x61
sd t1,ege
# sd a3,bce

# eki ^= di;
# bci = rol(eki,43);
ld t1,eki
# ld t2,di
li t3,43
xor t1,t1,t5
# rol a4,t1,t3
.byte 0x33,0x17,0xc3,0x61
sd t1,eki
# sd a4,bci

# emo ^= do;
# bco = rol(emo,21);
ld t1,emo
# ld t2,do
li t3,21
xor t1,t1,t6
# rol a5,t1,t3
.byte 0xb3,0x17,0xc3,0x61
sd t1,emo
# sd a5,bco

# esu ^= du;
# bcu = rol(esu,14);
ld t1,esu
# ld t2,du
li t3,14
xor t1,t1,t0
# rol a6,t1,t3
.byte 0x33,0x18,0xc3,0x61
sd t1,esu
# sd a6,bcu

# aba = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
sd t3,aba

# aba ^= keccakf_roundconstants[round + 1];
ld t1,loop_count_val
addi t1,t1,1
slli t1,t1,3
ld t2,round_constants_ptr
add t1,t2,t1
ld t1,0(t1)
xor t3,t3,t1
sd t3,aba

# abe = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,abe

# abi = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,abi

# abo = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,abo

# abu = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,abu

# ebo ^= do;
# bca = rol(ebo,28);
ld t1,ebo
# ld t2,do
li t3,28
xor t1,t1,t6
# rol a1,t1,t3
.byte 0xb3,0x15,0xc3,0x61
sd t1,ebo
# sd a1,bca

# egu ^= du;
# bce = rol(egu,20);
ld t1,egu
# ld t2,du
li t3,20
xor t1,t1,t0
# rol a3,t1,t3
.byte 0xb3,0x16,0xc3,0x61
sd t1,egu
# sd a3,bce

# eka ^= da;
# bci = rol(eka,3);
ld t1,eka
# ld t2,da
li t3,3
xor t1,t1,a7
# rol a4,t1,t3
.byte 0x33,0x17,0xc3,0x61
sd t1,eka
# sd a4,bci

# eme ^= de;
# bco = rol(eme,45);
ld t1,eme
# ld t2,de
li t3,45
xor t1,t1,t4
# rol a5,t1,t3
.byte 0xb3,0x17,0xc3,0x61
sd t1,eme
# sd a5,bco

# esi ^= di;
# bcu = rol(esi,61);
ld t1,esi
# ld t2,di
li t3,61
xor t1,t1,t5
# rol a6,t1,t3
.byte 0x33,0x18,0xc3,0x61
sd t1,esi
# sd a6,bcu

# aga = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
sd t3,aga

# age = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,age

# agi = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,agi

# ago = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,ago

# agu = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,agu

# ebe ^= de;
# bca = rol(ebe,1);
ld t1,ebe
# ld t2,de
li t3,1
xor t1,t1,t4
# rol a1,t1,t3
.byte 0xb3,0x15,0xc3,0x61
sd t1,ebe
# sd a1,bca

# egi ^= di;
# bce = rol(egi,6);
ld t1,egi
# ld t2,di
li t3,6
xor t1,t1,t5
# rol a3,t1,t3
.byte 0xb3,0x16,0xc3,0x61
sd t1,egi
# sd a3,bce

# eko ^= do;
# bci = rol(eko,25);
ld t1,eko
# ld t2,do
li t3,25
xor t1,t1,t6
# rol a4,t1,t3
.byte 0x33,0x17,0xc3,0x61
sd t1,eko
# sd a4,bci

# emu ^= du;
# bco = rol(emu,8);
ld t1,emu
# ld t2,du
li t3,8
xor t1,t1,t0
# rol a5,t1,t3
.byte 0xb3,0x17,0xc3,0x61
sd t1,emu
# sd a5,bco

# esa ^= da;
# bcu = rol(esa,18);
ld t1,esa
# ld t2,da
li t3,18
xor t1,t1,a7
# rol a6,t1,t3
.byte 0x33,0x18,0xc3,0x61
sd t1,esa
# sd a6,bcu

# aka = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
sd t3,aka

# ake = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,ake

# aki = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,aki

# ako = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,ako

# aku = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,aku

# ebu ^= du;
# bca = rol(ebu,27);
ld t1,ebu
# ld t2,du
li t3,27
xor t1,t1,t0
# rol a1,t1,t3
.byte 0xb3,0x15,0xc3,0x61
sd t1,ebu
# sd a1,bca

# ega ^= da;
# bce = rol(ega,36);
ld t1,ega
# ld t2,da
li t3,36
xor t1,t1,a7
# rol a3,t1,t3
.byte 0xb3,0x16,0xc3,0x61
sd t1,ega
# sd a3,bce

# eke ^= de;
# bci = rol(eke,10);
ld t1,eke
# ld t2,de
li t3,10
xor t1,t1,t4
# rol a4,t1,t3
.byte 0x33,0x17,0xc3,0x61
sd t1,eke
# sd a4,bci

# emi ^= di;
# bco = rol(emi,15);
ld t1,emi
# ld t2,di
li t3,15
xor t1,t1,t5
# rol a5,t1,t3
.byte 0xb3,0x17,0xc3,0x61
sd t1,emi
# sd a5,bco

# eso ^= do;
# bcu = rol(eso,56);
ld t1,eso
# ld t2,do
li t3,56
xor t1,t1,t6
# rol a6,t1,t3
.byte 0x33,0x18,0xc3,0x61
sd t1,eso
# sd a6,bcu

# ama = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
sd t3,ama

# ame = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,ame

# ami = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,ami

# amo = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,amo

# amu = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,amu

# ebi ^= di;
# bca = rol(ebi,62);
ld t1,ebi
# ld t2,di
li t3,62
xor t1,t1,t5
# rol a1,t1,t3
.byte 0xb3,0x15,0xc3,0x61
sd t1,ebi
# sd a1,bca

# ego ^= do;
# bce = rol(ego,55);
ld t1,ego
# ld t2,do
li t3,55
xor t1,t1,t6
# rol a3,t1,t3
.byte 0xb3,0x16,0xc3,0x61
sd t1,ego
# sd a3,bce

# eku ^= du;
# bci = rol(eku,39);
ld t1,eku
# ld t2,du
li t3,39
xor t1,t1,t0
# rol a4,t1,t3
.byte 0x33,0x17,0xc3,0x61
sd t1,eku
# sd a4,bci

# ema ^= da;
# bco = rol(ema,41);
ld t1,ema
# ld t2,da
li t3,41
xor t1,t1,a7
# rol a5,t1,t3
.byte 0xb3,0x17,0xc3,0x61
sd t1,ema
# sd a5,bco

# ese ^= de;
# bcu = rol(ese,2);
ld t1,ese
# ld t2,de
li t3,2
xor t1,t1,t4
# rol a6,t1,t3
.byte 0x33,0x18,0xc3,0x61
sd t1,ese
# sd a6,bcu

# asa = bca ^ ((~bce) & bci);
# ld t1,bca
# ld t2,bce
# ld t3,bci
# andn t3,a4,a3
.byte 0x33,0x7e,0xd7,0x40
xor t3,a1,t3
sd t3,asa

# ase = bce ^ ((~bci) & bco);
# ld t1,bce
# ld t2,bci
# ld t3,bco
# andn t3,a5,a4
.byte 0x33,0xfe,0xe7,0x40
xor t3,a3,t3
sd t3,ase

# asi = bci ^ ((~bco) & bcu);
# ld t1,bci
# ld t2,bco
# ld t3,bcu
# andn t3,a6,a5
.byte 0x33,0x7e,0xf8,0x40
xor t3,a4,t3
sd t3,asi

# aso = bco ^ ((~bcu) & bca);
# ld t1,bco
# ld t2,bcu
# ld t3,bca
# andn t3,a1,a6
.byte 0x33,0xfe,0x05,0x41
xor t3,a5,t3
sd t3,aso

# asu = bcu ^ ((~bca) & bce);
# ld t1,bcu
# ld t2,bca
# ld t3,bce
# andn t3,a3,a1
.byte 0x33,0xfe,0xb6,0x40
xor t3,a6,t3
sd t3,asu

# for (round = 0; round < nrounds; round += 2) {
ld t1,loop_count_val
addi t1,t1,2
sd t1,loop_count_val
li t2,nrounds
bgt t2,t1,for_begin

ret
