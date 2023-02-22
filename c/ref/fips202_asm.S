#define state_ptr a0
#define state_buf a2

#define NROUNDS 24
#define SP_CACHE_BUF_SIZE -280 // sp 5 * 7 * 8
#define SP_ROUND_CONSTANTS -288 // KeccakF_RoundConstants
#define SP_LOOP_COUNT_VAL -296 // round

#define ROUND_CONSTANTS_PTR SP_ROUND_CONSTANTS(sp)
#define LOOP_COUNT_VAL SP_LOOP_COUNT_VAL(sp)

#define Aba 0(state_ptr)
#define Abe 8(state_ptr)
#define Abi 16(state_ptr)
#define Abo 24(state_ptr)
#define Abu 32(state_ptr)

#define Aga 40(state_ptr)
#define Age 48(state_ptr)
#define Agi 56(state_ptr)
#define Ago 64(state_ptr)
#define Agu 72(state_ptr)

#define Aka 80(state_ptr)
#define Ake 88(state_ptr)
#define Aki 96(state_ptr)
#define Ako 104(state_ptr)
#define Aku 112(state_ptr)

#define Ama 120(state_ptr)
#define Ame 128(state_ptr)
#define Ami 136(state_ptr)
#define Amo 144(state_ptr)
#define Amu 152(state_ptr)

#define Asa 160(state_ptr)
#define Ase 168(state_ptr)
#define Asi 176(state_ptr)
#define Aso 184(state_ptr)
#define Asu 192(state_ptr)

#define BCa 0(state_buf)
#define BCe 8(state_buf)
#define BCi 16(state_buf)
#define BCo 24(state_buf)
#define BCu 32(state_buf)

#define Da 40(state_buf)
#define De 48(state_buf)
#define Di 56(state_buf)
#define Do 64(state_buf)
#define Du 72(state_buf)

#define Eba 80(state_buf)
#define Ebe 88(state_buf)
#define Ebi 96(state_buf)
#define Ebo 104(state_buf)
#define Ebu 112(state_buf)

#define Ega 120(state_buf)
#define Ege 128(state_buf)
#define Egi 136(state_buf)
#define Ego 144(state_buf)
#define Egu 152(state_buf)

#define Eka 160(state_buf)
#define Eke 168(state_buf)
#define Eki 176(state_buf)
#define Eko 184(state_buf)
#define Eku 192(state_buf)

#define Ema 200(state_buf)
#define Eme 208(state_buf)
#define Emi 216(state_buf)
#define Emo 224(state_buf)
#define Emu 232(state_buf)

#define Esa 240(state_buf)
#define Ese 248(state_buf)
#define Esi 256(state_buf)
#define Eso 264(state_buf)
#define Esu 272(state_buf)

# Registers that can be used:
# ra
# t0
# t1 ~ t6
# a0 ~ a7
#   a0 state ptr
#   a1 x KeccakF_RoundConstants
#   a2 state_buf
#   a3 x i (loop count))

#   a1 BCa
#   a3 BCe
#   a4 BCi
#   a5 BCo
#   a6 BCu

#   a7 Da
#   t4 De
#   t5 Di
#   t6 Do
#   t0 Du

.text
.globl riscv_keccak_f1600
.align 4
# a0 state ptr
# a1 KeccakF_RoundConstants
riscv_keccak_f1600:
  addi state_buf, sp, SP_CACHE_BUF_SIZE # sp need offset 5 * 7 * 8
  sd a1, ROUND_CONSTANTS_PTR
  
  li t1, 0
  sd t1, LOOP_COUNT_VAL
FOR_BEGIN:
  # BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
  ld t1, Aba
  ld t2, Aga
  xor a1, t1, t2
  ld t1, Aka
  ld t2, Ama
  xor a1, a1, t1
  xor a1, a1, t2
  ld t1, Asa
  xor a1, a1, t1
  # sd a1, BCa

  # BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
  ld t1, Abe
  ld t2, Age
  xor a3, t1, t2
  ld t1, Ake
  ld t2, Ame
  xor a3, a3, t1
  xor a3, a3, t2
  ld t1, Ase
  xor a3, a3, t1
  # sd a3, BCe

  # BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
  ld t1, Abi
  ld t2, Agi
  xor a4, t1, t2
  ld t1, Aki
  ld t2, Ami
  xor a4, a4, t1
  xor a4, a4, t2
  ld t1, Asi
  xor a4, a4, t1
  # sd a4, BCi

  # BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
  ld t1, Abo
  ld t2, Ago
  xor a5, t1, t2
  ld t1, Ako
  ld t2, Amo
  xor a5, a5, t1
  xor a5, a5, t2
  ld t1, Aso
  xor a5, a5, t1
  # sd a5, BCo

  # BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
  ld t1, Abu
  ld t2, Agu
  xor a6, t1, t2
  ld t1, Aku
  ld t2, Amu
  xor a6, a6, t1
  xor a6, a6, t2
  ld t1, Asu
  xor a6, a6, t1
  # sd a6, BCu

  li t1, 1
  # Da = BCu ^ ROL(BCe, 1);
  # ld t2, BCu
  # ld t3, BCe
  rol t3, a3, t1
  xor a7, a6, t3
  # sd a7, Da

  # De = BCa ^ ROL(BCi, 1);
  # ld t2, BCa
  # ld t3, BCi
  rol t3, a4, t1
  xor t4, a1, t3
  # sd t4, De

  # Di = BCe ^ ROL(BCo, 1);
  # ld t2, BCe
  # ld t3, BCo
  rol t3, a5, t1
  xor t5, a3, t3
  # sd t5, Di

  # Do = BCi ^ ROL(BCu, 1);
  # ld t2, BCi
  # ld t3, BCu
  rol t3, a6, t1
  xor t6, a4, t3
  # sd t6, Do

  # Du = BCo ^ ROL(BCa, 1);
  # ld t2, BCo
  # ld t3, BCa
  rol t3, a1, t1
  xor t0, a5, t3
  # sd t0, Du

  # Aba ^= Da;
  ld t1, Aba
  # ld t2, Da
  xor a1, t1, a7
  sd a1, Aba

  # BCa = Aba;
  # sd a1, BCa

  # Age ^= De;
  ld t1, Age
  # ld t2, De
  xor t1, t1, t4
  sd t1, Age

  # BCe = ROL(Age, 44);
  li t1, 44
  ld t2, Age
  rol a3, t2, t1
  # sd a3, BCe

  # Aki ^= Di;
  ld t1, Aki
  # ld t2, Di
  xor t1, t1, t5
  sd t1, Aki

  # BCi = ROL(Aki, 43);
  li t1, 43
  ld t2, Aki
  rol a4, t2, t1
  # sd a4, BCi

  # Amo ^= Do;
  ld t1, Amo
  # ld t2, Do
  xor t1, t1, t6
  sd t1, Amo

  # BCo = ROL(Amo, 21);
  li t1, 21
  ld t2, Amo
  rol a5, t2, t1
  # sd a5, BCo

  # Asu ^= Du;
  ld t1, Asu
  # ld t2, Du
  xor t1, t1, t0
  sd t1, Asu

  # BCu = ROL(Asu, 14);
  li t1, 14
  ld t2, Asu
  rol a6, t2, t1
  # sd a6, BCu

  # Eba = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  # sd t3, Eba

  # Eba ^= KeccakF_RoundConstants[round];
  ld t1, LOOP_COUNT_VAL
  slli t1, t1, 3
  ld t2, ROUND_CONSTANTS_PTR
  add t1, t2, t1
  ld t1, 0(t1)
  xor t3, t3, t1
  sd t3, Eba

  # Ebe = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Ebe

  # Ebi = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Ebi

  # Ebo = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Ebo

  # Ebu = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Ebu

  # Abo ^= Do;
  ld t1, Abo
  # ld t2, Do
  xor t1, t1, t6
  sd t1, Abo

  # BCa = ROL(Abo, 28);
  li t2, 28
  rol a1, t1, t2
  # sd t2, BCa

  # Agu ^= Du;
  ld t1, Agu
  # ld t2, Du
  xor t1, t1, t0
  sd t1, Agu

  # BCe = ROL(Agu, 20);
  li t2, 20
  rol a3, t1, t2
  # sd a3, BCe

  # Aka ^= Da;
  ld t1, Aka
  # ld t2, Da
  xor t1, t1, a7
  sd t1, Aka

  # BCi = ROL(Aka, 3);
  li t2, 3
  rol a4, t1, t2
  # sd a4, BCi
  
  # Ame ^= De;
  ld t1, Ame
  # ld t2, De
  xor t1, t1, t4
  sd t1, Ame

  # BCo = ROL(Ame, 45);
  li t2, 45
  rol a5, t1, t2
  # sd a5, BCo

  # Asi ^= Di;
  ld t1, Asi
  # ld t2, Di
  xor t1, t1, t5
  sd t1, Asi

  # BCu = ROL(Asi, 61);
  li t2, 61
  rol a6, t1, t2
  # sd a6, BCu

  # Ega = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  sd t3, Ega

  # Ege = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Ege

  # Egi = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Egi

  # Ego = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Ego

  # Egu = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Egu

  # Abe ^= De;
  # BCa = ROL(Abe, 1);
  ld t1, Abe
  # ld t2, De
  xor t1, t1, t4
  sd t1, Abe
  
  li t2, 1
  rol a1, t1, t2
  # sd a1, BCa

  # Agi ^= Di;
  # BCe = ROL(Agi, 6);
  ld t1, Agi
  # ld t2, Di
  xor t1, t1, t5
  sd t1, Agi
  
  li t2, 6
  rol a3, t1, t2
  # sd a3, BCe

  # Ako ^= Do;
  # BCi = ROL(Ako, 25);
  ld t1, Ako
  # ld t2, Do
  xor t1, t1, t6
  sd t1, Ako
  
  li t2, 25
  rol a4, t1, t2
  # sd a4, BCi

  # Amu ^= Du;
  # BCo = ROL(Amu, 8);
  ld t1, Amu
  # ld t2, Du
  xor t1, t1, t0
  sd t1, Amu
  
  li t2, 8
  rol a5, t1, t2
  # sd a5, BCo

  # Asa ^= Da;
  # BCu = ROL(Asa, 18);
  ld t1, Asa
  # ld t2, Da
  xor t1, t1, a7
  sd t1, Asa
  
  li t2, 18
  rol a6, t1, t2
  # sd a6, BCu

  # Eka = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  sd t3, Eka

  # Eke = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Eke

  # Eki = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Eki

  # Eko = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Eko

  # Eku = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Eku

  # Abu ^= Du;
  # BCa = ROL(Abu, 27);
  ld t1, Abu
  # ld t2, Du
  xor t1, t1, t0
  sd t1, Abu

  li t2, 27
  rol a1, t1, t2
  # sd t2, BCa

  # Aga ^= Da;
  # BCe = ROL(Aga, 36);
  ld t1, Aga
  # ld t2, Da
  xor t1, t1, a7
  sd t1, Aga

  li t2, 36
  rol a3, t1, t2
  # sd a3, BCe

  # Ake ^= De;
  # BCi = ROL(Ake, 10);
  ld t1, Ake
  # ld t2, De
  xor t1, t1, t4
  sd t1, Ake

  li t2, 10
  rol a4, t1, t2
  # sd a4, BCi

  # Ami ^= Di;
  # BCo = ROL(Ami, 15);
  ld t1, Ami
  # ld t2, Di
  xor t1, t1, t5
  sd t1, Ami

  li t2, 15
  rol a5, t1, t2
  # sd a5, BCo

  # Aso ^= Do;
  # BCu = ROL(Aso, 56);
  ld t1, Aso
  # ld t2, Do
  xor t1, t1, t6
  sd t1, Aso

  li t2, 56
  rol a6, t1, t2
  # sd a6, BCu

  # Ema = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  sd t3, Ema

  # Eme = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Eme

  # Emi = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Emi

  # Emo = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Emo

  # Emu = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Emu

  # Abi ^= Di;
  # BCa = ROL(Abi, 62);
  ld t1, Abi
  # ld t2, Di
  xor t1, t1, t5
  sd t1, Abi
  li t2, 62
  rol a1, t1, t2
  # sd a1, BCa
  
  # Ago ^= Do;
  # BCe = ROL(Ago, 55);
  ld t1, Ago
  # ld t2, Do
  xor t1, t1, t6
  sd t1, Ago
  li t2, 55
  rol a3, t1, t2
  # sd a3, BCe

  # Aku ^= Du;
  # BCi = ROL(Aku, 39);
  ld t1, Aku
  # ld t2, Du
  xor t1, t1, t0
  sd t1, Aku
  li t2, 39
  rol a4, t1, t2
  # sd a4, BCi

  # Ama ^= Da;
  # BCo = ROL(Ama, 41);
  ld t1, Ama
  # ld t2, Da
  xor t1, t1, a7
  sd t1, Ama
  li t2, 41
  rol a5, t1, t2
  # sd a5, BCo

  # Ase ^= De;
  # BCu = ROL(Ase, 2);
  ld t1, Ase
  # ld t2, De
  xor t1, t1, t4
  sd t1, Ase
  li t2, 2
  rol a6, t1, t2
  # sd a6, BCu

  # Esa = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  sd t3, Esa

  # Ese = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Ese

  # Esi = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Esi

  # Eso = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Eso

  # Esu = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Esu

  # BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
  ld t1, Eba
  ld t2, Ega
  xor a1, t1, t2
  ld t1, Eka
  ld t2, Ema
  xor a1, a1, t1
  xor a1, a1, t2
  ld t1, Esa
  xor a1, a1, t1
  # sd a1, BCa

  # BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
  ld t1, Ebe
  ld t2, Ege
  xor a3, t1, t2
  ld t1, Eke
  ld t2, Eme
  xor a3, a3, t1
  xor a3, a3, t2
  ld t1, Ese
  xor a3, a3, t1
  # sd a3, BCe

  # BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
  ld t1, Ebi
  ld t2, Egi
  xor a4, t1, t2
  ld t1, Eki
  ld t2, Emi
  xor a4, a4, t1
  xor a4, a4, t2
  ld t1, Esi
  xor a4, a4, t1
  # sd a4, BCi

  # BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
  ld t1, Ebo
  ld t2, Ego
  xor a5, t1, t2
  ld t1, Eko
  ld t2, Emo
  xor a5, a5, t1
  xor a5, a5, t2
  ld t1, Eso
  xor a5, a5, t1
  # sd a5, BCo

  # BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
  ld t1, Ebu
  ld t2, Egu
  xor a6, t1, t2
  ld t1, Eku
  ld t2, Emu
  xor a6, a6, t1
  xor a6, a6, t2
  ld t1, Esu
  xor a6, a6, t1
  # sd a6, BCu

  li t3, 1

  # Da = BCu ^ ROL(BCe, 1);
  # ld t1, BCu
  # ld t2, BCe
  rol t2, a3, t3
  xor a7, a6, t2
  # sd a7, Da

  # De = BCa ^ ROL(BCi, 1);
  # ld t1, BCa
  # ld t2, BCi
  rol t2, a4, t3
  xor t4, a1, t2
  # sd t4, De

  # Di = BCe ^ ROL(BCo, 1);
  # ld t1, BCe
  # ld t2, BCo
  rol t2, a5, t3
  xor t5, a3, t2
  # sd t5, Di

  # Do = BCi ^ ROL(BCu, 1);
  # ld t1, BCi
  # ld t2, BCu
  rol t2, a6, t3
  xor t6, a4, t2
  # sd t6, Do

  # Du = BCo ^ ROL(BCa, 1);
  # ld t1, BCo
  # ld t2, BCa
  rol t2, a1, t3
  xor t0, a5, t2
  # sd t0, Du

  # Eba ^= Da;
  # BCa = Eba;
  ld t1, Eba
  # ld t2, Da
  xor a1, t1, a7
  sd a1, Eba
  # sd a1, BCa

  # Ege ^= De;
  # BCe = ROL(Ege, 44);
  ld t1, Ege
  # ld t2, De
  li t3, 44
  xor t1, t1, t4
  rol a3, t1, t3
  sd t1, Ege
  # sd a3, BCe

  # Eki ^= Di;
  # BCi = ROL(Eki, 43);
  ld t1, Eki
  # ld t2, Di
  li t3, 43
  xor t1, t1, t5
  rol a4, t1, t3
  sd t1, Eki
  # sd a4, BCi

  # Emo ^= Do;
  # BCo = ROL(Emo, 21);
  ld t1, Emo
  # ld t2, Do
  li t3, 21
  xor t1, t1, t6
  rol a5, t1, t3
  sd t1, Emo
  # sd a5, BCo

  # Esu ^= Du;
  # BCu = ROL(Esu, 14);
  ld t1, Esu
  # ld t2, Du
  li t3, 14
  xor t1, t1, t0
  rol a6, t1, t3
  sd t1, Esu
  # sd a6, BCu

  # Aba = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  sd t3, Aba

  # Aba ^= KeccakF_RoundConstants[round + 1];
  ld t1, LOOP_COUNT_VAL
  addi t1, t1, 1
  slli t1, t1, 3
  ld t2, ROUND_CONSTANTS_PTR
  add t1, t2, t1
  ld t1, 0(t1)
  xor t3, t3, t1
  sd t3, Aba

  # Abe = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Abe

  # Abi = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Abi

  # Abo = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Abo

  # Abu = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Abu

  # Ebo ^= Do;
  # BCa = ROL(Ebo, 28);
  ld t1, Ebo
  # ld t2, Do
  li t3, 28
  xor t1, t1, t6
  rol a1, t1, t3
  sd t1, Ebo
  # sd a1, BCa

  # Egu ^= Du;
  # BCe = ROL(Egu, 20);
  ld t1, Egu
  # ld t2, Du
  li t3, 20
  xor t1, t1, t0
  rol a3, t1, t3
  sd t1, Egu
  # sd a3, BCe

  # Eka ^= Da;
  # BCi = ROL(Eka, 3);
  ld t1, Eka
  # ld t2, Da
  li t3, 3
  xor t1, t1, a7
  rol a4, t1, t3
  sd t1, Eka
  # sd a4, BCi

  # Eme ^= De;
  # BCo = ROL(Eme, 45);
  ld t1, Eme
  # ld t2, De
  li t3, 45
  xor t1, t1, t4
  rol a5, t1, t3
  sd t1, Eme
  # sd a5, BCo

  # Esi ^= Di;
  # BCu = ROL(Esi, 61);
  ld t1, Esi
  # ld t2, Di
  li t3, 61
  xor t1, t1, t5
  rol a6, t1, t3
  sd t1, Esi
  # sd a6, BCu

  # Aga = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  sd t3, Aga

  # Age = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Age

  # Agi = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Agi

  # Ago = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Ago

  # Agu = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Agu

  # Ebe ^= De;
  # BCa = ROL(Ebe, 1);
  ld t1, Ebe
  # ld t2, De
  li t3, 1
  xor t1, t1, t4
  rol a1, t1, t3
  sd t1, Ebe
  # sd a1, BCa

  # Egi ^= Di;
  # BCe = ROL(Egi, 6);
  ld t1, Egi
  # ld t2, Di
  li t3, 6
  xor t1, t1, t5
  rol a3, t1, t3
  sd t1, Egi
  # sd a3, BCe

  # Eko ^= Do;
  # BCi = ROL(Eko, 25);
  ld t1, Eko
  # ld t2, Do
  li t3, 25
  xor t1, t1, t6
  rol a4, t1, t3
  sd t1, Eko
  # sd a4, BCi

  # Emu ^= Du;
  # BCo = ROL(Emu, 8);
  ld t1, Emu
  # ld t2, Du
  li t3, 8
  xor t1, t1, t0
  rol a5, t1, t3
  sd t1, Emu
  # sd a5, BCo

  # Esa ^= Da;
  # BCu = ROL(Esa, 18);
  ld t1, Esa
  # ld t2, Da
  li t3, 18
  xor t1, t1, a7
  rol a6, t1, t3
  sd t1, Esa
  # sd a6, BCu

  # Aka = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  sd t3, Aka

  # Ake = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Ake

  # Aki = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Aki

  # Ako = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Ako
  
  # Aku = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Aku

  # Ebu ^= Du;
  # BCa = ROL(Ebu, 27);
  ld t1, Ebu
  # ld t2, Du
  li t3, 27
  xor t1, t1, t0
  rol a1, t1, t3
  sd t1, Ebu
  # sd a1, BCa

  # Ega ^= Da;
  # BCe = ROL(Ega, 36);
  ld t1, Ega
  # ld t2, Da
  li t3, 36
  xor t1, t1, a7
  rol a3, t1, t3
  sd t1, Ega
  # sd a3, BCe

  # Eke ^= De;
  # BCi = ROL(Eke, 10);
  ld t1, Eke
  # ld t2, De
  li t3, 10
  xor t1, t1, t4
  rol a4, t1, t3
  sd t1, Eke
  # sd a4, BCi

  # Emi ^= Di;
  # BCo = ROL(Emi, 15);
  ld t1, Emi
  # ld t2, Di
  li t3, 15
  xor t1, t1, t5
  rol a5, t1, t3
  sd t1, Emi
  # sd a5, BCo

  # Eso ^= Do;
  # BCu = ROL(Eso, 56);
  ld t1, Eso
  # ld t2, Do
  li t3, 56
  xor t1, t1, t6
  rol a6, t1, t3
  sd t1, Eso
  # sd a6, BCu

  # Ama = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  sd t3, Ama

  # Ame = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Ame

  # Ami = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Ami

  # Amo = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Amo

  # Amu = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Amu

  # Ebi ^= Di;
  # BCa = ROL(Ebi, 62);
  ld t1, Ebi
  # ld t2, Di
  li t3, 62
  xor t1, t1, t5
  rol a1, t1, t3
  sd t1, Ebi
  # sd a1, BCa

  # Ego ^= Do;
  # BCe = ROL(Ego, 55);
  ld t1, Ego
  # ld t2, Do
  li t3, 55
  xor t1, t1, t6
  rol a3, t1, t3
  sd t1, Ego
  # sd a3, BCe

  # Eku ^= Du;
  # BCi = ROL(Eku, 39);
  ld t1, Eku
  # ld t2, Du
  li t3, 39
  xor t1, t1, t0
  rol a4, t1, t3
  sd t1, Eku
  # sd a4, BCi

  # Ema ^= Da;
  # BCo = ROL(Ema, 41);
  ld t1, Ema
  # ld t2, Da
  li t3, 41
  xor t1, t1, a7
  rol a5, t1, t3
  sd t1, Ema
  # sd a5, BCo

  # Ese ^= De;
  # BCu = ROL(Ese, 2);
  ld t1, Ese
  # ld t2, De
  li t3, 2
  xor t1, t1, t4
  rol a6, t1, t3
  sd t1, Ese
  # sd a6, BCu

  # Asa = BCa ^ ((~BCe) & BCi);
  # ld t1, BCa
  # ld t2, BCe
  # ld t3, BCi
  andn t3, a4, a3
  xor t3, a1, t3
  sd t3, Asa

  # Ase = BCe ^ ((~BCi) & BCo);
  # ld t1, BCe
  # ld t2, BCi
  # ld t3, BCo
  andn t3, a5, a4
  xor t3, a3, t3
  sd t3, Ase

  # Asi = BCi ^ ((~BCo) & BCu);
  # ld t1, BCi
  # ld t2, BCo
  # ld t3, BCu
  andn t3, a6, a5
  xor t3, a4, t3
  sd t3, Asi

  # Aso = BCo ^ ((~BCu) & BCa);
  # ld t1, BCo
  # ld t2, BCu
  # ld t3, BCa
  andn t3, a1, a6
  xor t3, a5, t3
  sd t3, Aso

  # Asu = BCu ^ ((~BCa) & BCe);
  # ld t1, BCu
  # ld t2, BCa
  # ld t3, BCe
  andn t3, a3, a1
  xor t3, a6, t3
  sd t3, Asu

  # for (round = 0; round < NROUNDS; round += 2) {
  ld t1, LOOP_COUNT_VAL
  addi t1, t1, 2
  sd t1, LOOP_COUNT_VAL
  li t2, NROUNDS
  bgt t2, t1, FOR_BEGIN

  ret