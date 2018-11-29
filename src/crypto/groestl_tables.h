// Copyright (c) 2018 Jyocoin Project, Derived from 2014-2018, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef __tables_h
#define __tables_h

#include "common/int-util.h"


#if BYTE_ORDER == LITTLE_ENDIAN
const uint32_t T[512] = {0xa5f432c6, 0xc6a597f4, 0x84976ff8, 0xf884eb97, 0x99b05eee, 0xee99c7b0, 0x8d8c7af6, 0xf68df78c, 0xd17e8ff, 0xff0de517, 0xbddc0ad6, 0xd6bdb7dc, 0xb1c816de, 0xdeb1a7c8, 0x54fc6d91, 0x915439fc
, 0x50f09060, 0x6050c0f0, 0x3050702, 0x2030405, 0xa9e02ece, 0xcea987e0, 0x7d87d156, 0x567dac87, 0x192bcce7, 0xe719d52b, 0x62a613b5, 0xb56271a6, 0xe6317c4d, 0x4de69a31, 0x9ab559ec, 0xec9ac3b5
, 0x45cf408f, 0x8f4505cf, 0x9dbca31f, 0x1f9d3ebc, 0x40c04989, 0x894009c0, 0x879268fa, 0xfa87ef92, 0x153fd0ef, 0xef15c53f, 0xeb2694b2, 0xb2eb7f26, 0xc940ce8e, 0x8ec90740, 0xb1de6fb, 0xfb0bed1d
, 0xec2f6e41, 0x41ec822f, 0x67a91ab3, 0xb3677da9, 0xfd1c435f, 0x5ffdbe1c, 0xea256045, 0x45ea8a25, 0xbfdaf923, 0x23bf46da, 0xf7025153, 0x53f7a602, 0x96a145e4, 0xe496d3a1, 0x5bed769b, 0x9b5b2ded
, 0xc25d2875, 0x75c2ea5d, 0x1c24c5e1, 0xe11cd924, 0xaee9d43d, 0x3dae7ae9, 0x6abef24c, 0x4c6a98be, 0x5aee826c, 0x6c5ad8ee, 0x41c3bd7e, 0x7e41fcc3, 0x206f3f5, 0xf502f106, 0x4fd15283, 0x834f1dd1
, 0x5ce48c68, 0x685cd0e4, 0xf4075651, 0x51f4a207, 0x345c8dd1, 0xd134b95c, 0x818e1f9, 0xf908e918, 0x93ae4ce2, 0xe293dfae, 0x73953eab, 0xab734d95, 0x53f59762, 0x6253c4f5, 0x3f416b2a, 0x2a3f5441
, 0xc141c08, 0x80c1014, 0x52f66395, 0x955231f6, 0x65afe946, 0x46658caf, 0x5ee27f9d, 0x9d5e21e2, 0x28784830, 0x30286078, 0xa1f8cf37, 0x37a16ef8, 0xf111b0a, 0xa0f1411, 0xb5c4eb2f, 0x2fb55ec4
, 0x91b150e, 0xe091c1b, 0x365a7e24, 0x2436485a, 0x9bb6ad1b, 0x1b9b36b6, 0x3d4798df, 0xdf3da547, 0x266aa7cd, 0xcd26816a, 0x69bbf54e, 0x4e699cbb, 0xcd4c337f, 0x7fcdfe4c, 0x9fba50ea, 0xea9fcfba
, 0x1b2d3f12, 0x121b242d, 0x9eb9a41d, 0x1d9e3ab9, 0x749cc458, 0x5874b09c, 0x2e724634, 0x342e6872, 0x2d774136, 0x362d6c77, 0xb2cd11dc, 0xdcb2a3cd, 0xee299db4, 0xb4ee7329, 0xfb164d5b, 0x5bfbb616
, 0xf601a5a4, 0xa4f65301, 0x4dd7a176, 0x764decd7, 0x61a314b7, 0xb76175a3, 0xce49347d, 0x7dcefa49, 0x7b8ddf52, 0x527ba48d, 0x3e429fdd, 0xdd3ea142, 0x7193cd5e, 0x5e71bc93, 0x97a2b113, 0x139726a2
, 0xf504a2a6, 0xa6f55704, 0x68b801b9, 0xb96869b8, 0x0, 0x0, 0x2c74b5c1, 0xc12c9974, 0x60a0e040, 0x406080a0, 0x1f21c2e3, 0xe31fdd21, 0xc8433a79, 0x79c8f243, 0xed2c9ab6, 0xb6ed772c
, 0xbed90dd4, 0xd4beb3d9, 0x46ca478d, 0x8d4601ca, 0xd9701767, 0x67d9ce70, 0x4bddaf72, 0x724be4dd, 0xde79ed94, 0x94de3379, 0xd467ff98, 0x98d42b67, 0xe82393b0, 0xb0e87b23, 0x4ade5b85, 0x854a11de
, 0x6bbd06bb, 0xbb6b6dbd, 0x2a7ebbc5, 0xc52a917e, 0xe5347b4f, 0x4fe59e34, 0x163ad7ed, 0xed16c13a, 0xc554d286, 0x86c51754, 0xd762f89a, 0x9ad72f62, 0x55ff9966, 0x6655ccff, 0x94a7b611, 0x119422a7
, 0xcf4ac08a, 0x8acf0f4a, 0x1030d9e9, 0xe910c930, 0x60a0e04, 0x406080a, 0x819866fe, 0xfe81e798, 0xf00baba0, 0xa0f05b0b, 0x44ccb478, 0x7844f0cc, 0xbad5f025, 0x25ba4ad5, 0xe33e754b, 0x4be3963e
, 0xf30eaca2, 0xa2f35f0e, 0xfe19445d, 0x5dfeba19, 0xc05bdb80, 0x80c01b5b, 0x8a858005, 0x58a0a85, 0xadecd33f, 0x3fad7eec, 0xbcdffe21, 0x21bc42df, 0x48d8a870, 0x7048e0d8, 0x40cfdf1, 0xf104f90c
, 0xdf7a1963, 0x63dfc67a, 0xc1582f77, 0x77c1ee58, 0x759f30af, 0xaf75459f, 0x63a5e742, 0x426384a5, 0x30507020, 0x20304050, 0x1a2ecbe5, 0xe51ad12e, 0xe12effd, 0xfd0ee112, 0x6db708bf, 0xbf6d65b7
, 0x4cd45581, 0x814c19d4, 0x143c2418, 0x1814303c, 0x355f7926, 0x26354c5f, 0x2f71b2c3, 0xc32f9d71, 0xe13886be, 0xbee16738, 0xa2fdc835, 0x35a26afd, 0xcc4fc788, 0x88cc0b4f, 0x394b652e, 0x2e395c4b
, 0x57f96a93, 0x93573df9, 0xf20d5855, 0x55f2aa0d, 0x829d61fc, 0xfc82e39d, 0x47c9b37a, 0x7a47f4c9, 0xacef27c8, 0xc8ac8bef, 0xe73288ba, 0xbae76f32, 0x2b7d4f32, 0x322b647d, 0x95a442e6, 0xe695d7a4
, 0xa0fb3bc0, 0xc0a09bfb, 0x98b3aa19, 0x199832b3, 0xd168f69e, 0x9ed12768, 0x7f8122a3, 0xa37f5d81, 0x66aaee44, 0x446688aa, 0x7e82d654, 0x547ea882, 0xabe6dd3b, 0x3bab76e6, 0x839e950b, 0xb83169e
, 0xca45c98c, 0x8cca0345, 0x297bbcc7, 0xc729957b, 0xd36e056b, 0x6bd3d66e, 0x3c446c28, 0x283c5044, 0x798b2ca7, 0xa779558b, 0xe23d81bc, 0xbce2633d, 0x1d273116, 0x161d2c27, 0x769a37ad, 0xad76419a
, 0x3b4d96db, 0xdb3bad4d, 0x56fa9e64, 0x6456c8fa, 0x4ed2a674, 0x744ee8d2, 0x1e223614, 0x141e2822, 0xdb76e492, 0x92db3f76, 0xa1e120c, 0xc0a181e, 0x6cb4fc48, 0x486c90b4, 0xe4378fb8, 0xb8e46b37
, 0x5de7789f, 0x9f5d25e7, 0x6eb20fbd, 0xbd6e61b2, 0xef2a6943, 0x43ef862a, 0xa6f135c4, 0xc4a693f1, 0xa8e3da39, 0x39a872e3, 0xa4f7c631, 0x31a462f7, 0x37598ad3, 0xd337bd59, 0x8b8674f2, 0xf28bff86
, 0x325683d5, 0xd532b156, 0x43c54e8b, 0x8b430dc5, 0x59eb856e, 0x6e59dceb, 0xb7c218da, 0xdab7afc2, 0x8c8f8e01, 0x18c028f, 0x64ac1db1, 0xb16479ac, 0xd26df19c, 0x9cd2236d, 0xe03b7249, 0x49e0923b
, 0xb4c71fd8, 0xd8b4abc7, 0xfa15b9ac, 0xacfa4315, 0x709faf3, 0xf307fd09, 0x256fa0cf, 0xcf25856f, 0xafea20ca, 0xcaaf8fea, 0x8e897df4, 0xf48ef389, 0xe9206747, 0x47e98e20, 0x18283810, 0x10182028
, 0xd5640b6f, 0x6fd5de64, 0x888373f0, 0xf088fb83, 0x6fb1fb4a, 0x4a6f94b1, 0x7296ca5c, 0x5c72b896, 0x246c5438, 0x3824706c, 0xf1085f57, 0x57f1ae08, 0xc7522173, 0x73c7e652, 0x51f36497, 0x975135f3
, 0x2365aecb, 0xcb238d65, 0x7c8425a1, 0xa17c5984, 0x9cbf57e8, 0xe89ccbbf, 0x21635d3e, 0x3e217c63, 0xdd7cea96, 0x96dd377c, 0xdc7f1e61, 0x61dcc27f, 0x86919c0d, 0xd861a91, 0x85949b0f, 0xf851e94
, 0x90ab4be0, 0xe090dbab, 0x42c6ba7c, 0x7c42f8c6, 0xc4572671, 0x71c4e257, 0xaae529cc, 0xccaa83e5, 0xd873e390, 0x90d83b73, 0x50f0906, 0x6050c0f, 0x103f4f7, 0xf701f503, 0x12362a1c, 0x1c123836
, 0xa3fe3cc2, 0xc2a39ffe, 0x5fe18b6a, 0x6a5fd4e1, 0xf910beae, 0xaef94710, 0xd06b0269, 0x69d0d26b, 0x91a8bf17, 0x17912ea8, 0x58e87199, 0x995829e8, 0x2769533a, 0x3a277469, 0xb9d0f727, 0x27b94ed0
, 0x384891d9, 0xd938a948, 0x1335deeb, 0xeb13cd35, 0xb3cee52b, 0x2bb356ce, 0x33557722, 0x22334455, 0xbbd604d2, 0xd2bbbfd6, 0x709039a9, 0xa9704990, 0x89808707, 0x7890e80, 0xa7f2c133, 0x33a766f2
, 0xb6c1ec2d, 0x2db65ac1, 0x22665a3c, 0x3c227866, 0x92adb815, 0x15922aad, 0x2060a9c9, 0xc9208960, 0x49db5c87, 0x874915db, 0xff1ab0aa, 0xaaff4f1a, 0x7888d850, 0x5078a088, 0x7a8e2ba5, 0xa57a518e
, 0x8f8a8903, 0x38f068a, 0xf8134a59, 0x59f8b213, 0x809b9209, 0x980129b, 0x1739231a, 0x1a173439, 0xda751065, 0x65daca75, 0x315384d7, 0xd731b553, 0xc651d584, 0x84c61351, 0xb8d303d0, 0xd0b8bbd3
, 0xc35edc82, 0x82c31f5e, 0xb0cbe229, 0x29b052cb, 0x7799c35a, 0x5a77b499, 0x11332d1e, 0x1e113c33, 0xcb463d7b, 0x7bcbf646, 0xfc1fb7a8, 0xa8fc4b1f, 0xd6610c6d, 0x6dd6da61, 0x3a4e622c, 0x2c3a584e};
#else
const uint32_t T[512] = {0xc632f4a5, 0xf497a5c6, 0xf86f9784, 0x97eb84f8, 0xee5eb099, 0xb0c799ee, 0xf67a8c8d, 0x8cf78df6, 0xffe8170d, 0x17e50dff, 0xd60adcbd, 0xdcb7bdd6, 0xde16c8b1, 0xc8a7b1de, 0x916dfc54, 0xfc395491
, 0x6090f050, 0xf0c05060, 0x02070503, 0x05040302, 0xce2ee0a9, 0xe087a9ce, 0x56d1877d, 0x87ac7d56, 0xe7cc2b19, 0x2bd519e7, 0xb513a662, 0xa67162b5, 0x4d7c31e6, 0x319ae64d, 0xec59b59a, 0xb5c39aec
, 0x8f40cf45, 0xcf05458f, 0x1fa3bc9d, 0xbc3e9d1f, 0x8949c040, 0xc0094089, 0xfa689287, 0x92ef87fa, 0xefd03f15, 0x3fc515ef, 0xb29426eb, 0x267febb2, 0x8ece40c9, 0x4007c98e, 0xfbe61d0b, 0x1ded0bfb
, 0x416e2fec, 0x2f82ec41, 0xb31aa967, 0xa97d67b3, 0x5f431cfd, 0x1cbefd5f, 0x456025ea, 0x258aea45, 0x23f9dabf, 0xda46bf23, 0x535102f7, 0x02a6f753, 0xe445a196, 0xa1d396e4, 0x9b76ed5b, 0xed2d5b9b
, 0x75285dc2, 0x5deac275, 0xe1c5241c, 0x24d91ce1, 0x3dd4e9ae, 0xe97aae3d, 0x4cf2be6a, 0xbe986a4c, 0x6c82ee5a, 0xeed85a6c, 0x7ebdc341, 0xc3fc417e, 0xf5f30602, 0x06f102f5, 0x8352d14f, 0xd11d4f83
, 0x688ce45c, 0xe4d05c68, 0x515607f4, 0x07a2f451, 0xd18d5c34, 0x5cb934d1, 0xf9e11808, 0x18e908f9, 0xe24cae93, 0xaedf93e2, 0xab3e9573, 0x954d73ab, 0x6297f553, 0xf5c45362, 0x2a6b413f, 0x41543f2a
, 0x081c140c, 0x14100c08, 0x9563f652, 0xf6315295, 0x46e9af65, 0xaf8c6546, 0x9d7fe25e, 0xe2215e9d, 0x30487828, 0x78602830, 0x37cff8a1, 0xf86ea137, 0x0a1b110f, 0x11140f0a, 0x2febc4b5, 0xc45eb52f
, 0x0e151b09, 0x1b1c090e, 0x247e5a36, 0x5a483624, 0x1badb69b, 0xb6369b1b, 0xdf98473d, 0x47a53ddf, 0xcda76a26, 0x6a8126cd, 0x4ef5bb69, 0xbb9c694e, 0x7f334ccd, 0x4cfecd7f, 0xea50ba9f, 0xbacf9fea
, 0x123f2d1b, 0x2d241b12, 0x1da4b99e, 0xb93a9e1d, 0x58c49c74, 0x9cb07458, 0x3446722e, 0x72682e34, 0x3641772d, 0x776c2d36, 0xdc11cdb2, 0xcda3b2dc, 0xb49d29ee, 0x2973eeb4, 0x5b4d16fb, 0x16b6fb5b
, 0xa4a501f6, 0x0153f6a4, 0x76a1d74d, 0xd7ec4d76, 0xb714a361, 0xa37561b7, 0x7d3449ce, 0x49face7d, 0x52df8d7b, 0x8da47b52, 0xdd9f423e, 0x42a13edd, 0x5ecd9371, 0x93bc715e, 0x13b1a297, 0xa2269713
, 0xa6a204f5, 0x0457f5a6, 0xb901b868, 0xb86968b9, 0x00000000, 0x00000000, 0xc1b5742c, 0x74992cc1, 0x40e0a060, 0xa0806040, 0xe3c2211f, 0x21dd1fe3, 0x793a43c8, 0x43f2c879, 0xb69a2ced, 0x2c77edb6
, 0xd40dd9be, 0xd9b3bed4, 0x8d47ca46, 0xca01468d, 0x671770d9, 0x70ced967, 0x72afdd4b, 0xdde44b72, 0x94ed79de, 0x7933de94, 0x98ff67d4, 0x672bd498, 0xb09323e8, 0x237be8b0, 0x855bde4a, 0xde114a85
, 0xbb06bd6b, 0xbd6d6bbb, 0xc5bb7e2a, 0x7e912ac5, 0x4f7b34e5, 0x349ee54f, 0xedd73a16, 0x3ac116ed, 0x86d254c5, 0x5417c586, 0x9af862d7, 0x622fd79a, 0x6699ff55, 0xffcc5566, 0x11b6a794, 0xa7229411
, 0x8ac04acf, 0x4a0fcf8a, 0xe9d93010, 0x30c910e9, 0x040e0a06, 0x0a080604, 0xfe669881, 0x98e781fe, 0xa0ab0bf0, 0x0b5bf0a0, 0x78b4cc44, 0xccf04478, 0x25f0d5ba, 0xd54aba25, 0x4b753ee3, 0x3e96e34b
, 0xa2ac0ef3, 0x0e5ff3a2, 0x5d4419fe, 0x19bafe5d, 0x80db5bc0, 0x5b1bc080, 0x0580858a, 0x850a8a05, 0x3fd3ecad, 0xec7ead3f, 0x21fedfbc, 0xdf42bc21, 0x70a8d848, 0xd8e04870, 0xf1fd0c04, 0x0cf904f1
, 0x63197adf, 0x7ac6df63, 0x772f58c1, 0x58eec177, 0xaf309f75, 0x9f4575af, 0x42e7a563, 0xa5846342, 0x20705030, 0x50403020, 0xe5cb2e1a, 0x2ed11ae5, 0xfdef120e, 0x12e10efd, 0xbf08b76d, 0xb7656dbf
, 0x8155d44c, 0xd4194c81, 0x18243c14, 0x3c301418, 0x26795f35, 0x5f4c3526, 0xc3b2712f, 0x719d2fc3, 0xbe8638e1, 0x3867e1be, 0x35c8fda2, 0xfd6aa235, 0x88c74fcc, 0x4f0bcc88, 0x2e654b39, 0x4b5c392e
, 0x936af957, 0xf93d5793, 0x55580df2, 0x0daaf255, 0xfc619d82, 0x9de382fc, 0x7ab3c947, 0xc9f4477a, 0xc827efac, 0xef8bacc8, 0xba8832e7, 0x326fe7ba, 0x324f7d2b, 0x7d642b32, 0xe642a495, 0xa4d795e6
, 0xc03bfba0, 0xfb9ba0c0, 0x19aab398, 0xb3329819, 0x9ef668d1, 0x6827d19e, 0xa322817f, 0x815d7fa3, 0x44eeaa66, 0xaa886644, 0x54d6827e, 0x82a87e54, 0x3bdde6ab, 0xe676ab3b, 0x0b959e83, 0x9e16830b
, 0x8cc945ca, 0x4503ca8c, 0xc7bc7b29, 0x7b9529c7, 0x6b056ed3, 0x6ed6d36b, 0x286c443c, 0x44503c28, 0xa72c8b79, 0x8b5579a7, 0xbc813de2, 0x3d63e2bc, 0x1631271d, 0x272c1d16, 0xad379a76, 0x9a4176ad
, 0xdb964d3b, 0x4dad3bdb, 0x649efa56, 0xfac85664, 0x74a6d24e, 0xd2e84e74, 0x1436221e, 0x22281e14, 0x92e476db, 0x763fdb92, 0x0c121e0a, 0x1e180a0c, 0x48fcb46c, 0xb4906c48, 0xb88f37e4, 0x376be4b8
, 0x9f78e75d, 0xe7255d9f, 0xbd0fb26e, 0xb2616ebd, 0x43692aef, 0x2a86ef43, 0xc435f1a6, 0xf193a6c4, 0x39dae3a8, 0xe372a839, 0x31c6f7a4, 0xf762a431, 0xd38a5937, 0x59bd37d3, 0xf274868b, 0x86ff8bf2
, 0xd5835632, 0x56b132d5, 0x8b4ec543, 0xc50d438b, 0x6e85eb59, 0xebdc596e, 0xda18c2b7, 0xc2afb7da, 0x018e8f8c, 0x8f028c01, 0xb11dac64, 0xac7964b1, 0x9cf16dd2, 0x6d23d29c, 0x49723be0, 0x3b92e049
, 0xd81fc7b4, 0xc7abb4d8, 0xacb915fa, 0x1543faac, 0xf3fa0907, 0x09fd07f3, 0xcfa06f25, 0x6f8525cf, 0xca20eaaf, 0xea8fafca, 0xf47d898e, 0x89f38ef4, 0x476720e9, 0x208ee947, 0x10382818, 0x28201810
, 0x6f0b64d5, 0x64ded56f, 0xf0738388, 0x83fb88f0, 0x4afbb16f, 0xb1946f4a, 0x5cca9672, 0x96b8725c, 0x38546c24, 0x6c702438, 0x575f08f1, 0x08aef157, 0x732152c7, 0x52e6c773, 0x9764f351, 0xf3355197
, 0xcbae6523, 0x658d23cb, 0xa125847c, 0x84597ca1, 0xe857bf9c, 0xbfcb9ce8, 0x3e5d6321, 0x637c213e, 0x96ea7cdd, 0x7c37dd96, 0x611e7fdc, 0x7fc2dc61, 0x0d9c9186, 0x911a860d, 0x0f9b9485, 0x941e850f
, 0xe04bab90, 0xabdb90e0, 0x7cbac642, 0xc6f8427c, 0x712657c4, 0x57e2c471, 0xcc29e5aa, 0xe583aacc, 0x90e373d8, 0x733bd890, 0x06090f05, 0x0f0c0506, 0xf7f40301, 0x03f501f7, 0x1c2a3612, 0x3638121c
, 0xc23cfea3, 0xfe9fa3c2, 0x6a8be15f, 0xe1d45f6a, 0xaebe10f9, 0x1047f9ae, 0x69026bd0, 0x6bd2d069, 0x17bfa891, 0xa82e9117, 0x9971e858, 0xe8295899, 0x3a536927, 0x6974273a, 0x27f7d0b9, 0xd04eb927
, 0xd9914838, 0x48a938d9, 0xebde3513, 0x35cd13eb, 0x2be5ceb3, 0xce56b32b, 0x22775533, 0x55443322, 0xd204d6bb, 0xd6bfbbd2, 0xa9399070, 0x904970a9, 0x07878089, 0x800e8907, 0x33c1f2a7, 0xf266a733
, 0x2decc1b6, 0xc15ab62d, 0x3c5a6622, 0x6678223c, 0x15b8ad92, 0xad2a9215, 0xc9a96020, 0x608920c9, 0x875cdb49, 0xdb154987, 0xaab01aff, 0x1a4fffaa, 0x50d88878, 0x88a07850, 0xa52b8e7a, 0x8e517aa5
, 0x03898a8f, 0x8a068f03, 0x594a13f8, 0x13b2f859, 0x09929b80, 0x9b128009, 0x1a233917, 0x3934171a, 0x651075da, 0x75cada65, 0xd7845331, 0x53b531d7, 0x84d551c6, 0x5113c684, 0xd003d3b8, 0xd3bbb8d0
, 0x82dc5ec3, 0x5e1fc382, 0x29e2cbb0, 0xcb52b029, 0x5ac39977, 0x99b4775a, 0x1e2d3311, 0x333c111e, 0x7b3d46cb, 0x46f6cb7b, 0xa8b71ffc, 0x1f4bfca8, 0x6d0c61d6, 0x61dad66d, 0x2c624e3a, 0x4e583a2c};
#endif

#endif /* __tables_h */
