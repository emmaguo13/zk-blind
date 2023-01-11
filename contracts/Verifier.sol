//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// 2019 OKIMS
//      ported to solidity 0.6
//      fixed linter warnings
//      added requiere error messages
//
//
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.6.11;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() internal pure returns (G2Point memory) {
        // Original code point
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );

/*
        // Changed by Jordi point
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
*/
    }
    /// @return r the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) internal pure returns (G1Point memory r) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success,"pairing-add-failed");
    }
    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success,"pairing-mul-failed");
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length,"pairing-lengths-failed");
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint[1] memory out;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success,"pairing-opcode-failed");
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alfa1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }
    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }
    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alfa1 = Pairing.G1Point(
            20491192805390485299153009773594534940189261866228447918068658471970481763042,
            9383485363053290200918347156157836566562967994039712273449902621266178545958
        );

        vk.beta2 = Pairing.G2Point(
            [4252822878758300859123897981450591353533073413197771768651442665752259397132,
             6375614351688725206403948262868962793625744043794305715222011528459656738731],
            [21847035105528745403288232691147584728191162732299865338377159692350059136679,
             10505242626370262277552901082094356697409835680220590971873171140371331206856]
        );
        vk.gamma2 = Pairing.G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
        vk.delta2 = Pairing.G2Point(
            [21682896353264444951301275286718818687092714016392231915628259584211815394573,
             21488637110526967717745083395301012514772358743592072085076130495496992754627],
            [3310576057091956602633940495488982923772175047903329588732333005806978173276,
             20275399160204223393297929727012561127329395498289778610055363804452315143677]
        );
        vk.IC = new Pairing.G1Point[](49);
        
        vk.IC[0] = Pairing.G1Point( 
            11989336131577629342013079938698468205759283599365930680156135773519131102015,
            5501651835555889635450055186330566334399336299717206785266098523970285781879
        );                                      
        
        vk.IC[1] = Pairing.G1Point( 
            19519262714101980701843137874873030410366491089999764047379783833046732849020,
            7157500756287161342483848569241211103127466798812643117185877250324280492464
        );                                      
        
        vk.IC[2] = Pairing.G1Point( 
            13624763916275729159459441624085766163286271718577328103711833812664878781726,
            15572587859806873721770584328012581200771744218698321486276983796179556713099
        );                                      
        
        vk.IC[3] = Pairing.G1Point( 
            13031977169654103531554068662871931378128044770437138739345031026834233795680,
            13389889253885659254080979152314014255263279836588887509858879465475296919798
        );                                      
        
        vk.IC[4] = Pairing.G1Point( 
            665626791644006289930719981151226434325337855369323522533220855074463766408,
            6705651877328467184647953340285734905642750385212533734008362099347913456198
        );                                      
        
        vk.IC[5] = Pairing.G1Point( 
            5612402352878396381835063525679656112490865095045347444483377566492893709643,
            1911210163751126627828066233961942015499449906045971237329896959886114869777
        );                                      
        
        vk.IC[6] = Pairing.G1Point( 
            17136269643733302105260798575827369016892803225608717440638788037046464330914,
            11353452425846230479602407148606489350919260516905429612860466679547032245086
        );                                      
        
        vk.IC[7] = Pairing.G1Point( 
            17312079768238846743527638361685520812955501339089697125440927686563626977188,
            7525541779090982451978366648134494816306347032071284032296449537807956127305
        );                                      
        
        vk.IC[8] = Pairing.G1Point( 
            12104597744120399043744183238217422871406806071888751014658088838915000160140,
            7426140716353750196365272842725761196740399581720425565431647781892865020240
        );                                      
        
        vk.IC[9] = Pairing.G1Point( 
            20619092409200530395225309021497334582464631840938739527380632073516402797133,
            19491445741838270447558182149599586023991333489531190032283956191987859843224
        );                                      
        
        vk.IC[10] = Pairing.G1Point( 
            6026885961037976151156275177225575221722403465965561959287906089263318275177,
            2171913659002222136060044215984256756128090958290437519823755190879416516024
        );                                      
        
        vk.IC[11] = Pairing.G1Point( 
            10196765761423959544754526574409938399686074605279500320571701974175958970400,
            8331481147041170626374514288869632000371140767035113958206390206080291229841
        );                                      
        
        vk.IC[12] = Pairing.G1Point( 
            4873588195038893279034032934507250824324431229216814738650836154865402366756,
            341045671296687243248661192420191379314863324063605783409526354841559961328
        );                                      
        
        vk.IC[13] = Pairing.G1Point( 
            14102525488433449879872886259124980744600950626884008412348224248689236397540,
            20960709123150424698593900639639451569587625934182537242922304856586508582901
        );                                      
        
        vk.IC[14] = Pairing.G1Point( 
            8815846521214511930068393313868515527292748345721332774283556600163657870397,
            14942427277048265752094015321628245815947809198044835781209369181136743410714
        );                                      
        
        vk.IC[15] = Pairing.G1Point( 
            11690680005144899273933840693320899233061494817832421221330501873836841543533,
            10931516853983221715308164511387421095148706998263071316657821455336851291767
        );                                      
        
        vk.IC[16] = Pairing.G1Point( 
            9057131024279865529490785966030944516644763370544731202439598935022375464766,
            2840399902198043723666332136265980473366941571493542493233284522571074960611
        );                                      
        
        vk.IC[17] = Pairing.G1Point( 
            11497090916603969175061599939016145526595157244787594073296595000761260861983,
            2721443385346533840410509737558065980052346092232977030669870525290440241135
        );                                      
        
        vk.IC[18] = Pairing.G1Point( 
            7660559237813158070832925325700759901679638718222186150600880154420817702446,
            6478047923654651679840136518573787780274210065588831456679544804946953054712
        );                                      
        
        vk.IC[19] = Pairing.G1Point( 
            19186637626291778361520225341778950407397062696798596530052343910085916035371,
            1482471213054134421535055306657741876961702969574660251109305203394142709758
        );                                      
        
        vk.IC[20] = Pairing.G1Point( 
            17297858794017236814227194541511372898120550511280178898142532301309000118204,
            15257888654108638001357962374441121028506540872007029146836074415576026881621
        );                                      
        
        vk.IC[21] = Pairing.G1Point( 
            10322550199130638985342682083920762973434990865209769702287001295026864766910,
            4128752822096656577415259054377814688060219656286538495655625229239905294606
        );                                      
        
        vk.IC[22] = Pairing.G1Point( 
            5826577024759345420254999824978485367642370330618338106481309914733895934855,
            8420701468312082298010639477499191816487570710391322168684887916235797962076
        );                                      
        
        vk.IC[23] = Pairing.G1Point( 
            96076473540746593462354809331460548571117656418733934499614450020333922316,
            16204144942804874871919997384007877547156652326163758026158577760781318708407
        );                                      
        
        vk.IC[24] = Pairing.G1Point( 
            10056456142513009321012676940269995925147175758976522489633350514644519448410,
            13661085333950955720065783777849435914817320577047182373305211198030190529397
        );                                      
        
        vk.IC[25] = Pairing.G1Point( 
            13575283520166062095676069680867788505784270437043808579289082042093586950015,
            1505409904397894522642432940337454436296254496263878975946897171492098413730
        );                                      
        
        vk.IC[26] = Pairing.G1Point( 
            10792714468549931713945902452588124233333810498104275839160832403142194660272,
            5900496354046412670397138776022418214619103004104355343141774979056858426742
        );                                      
        
        vk.IC[27] = Pairing.G1Point( 
            32383694678889260739444398089590804340258752305040495443211152521355731835,
            19708243326152477153999454883714790810208136353589241067267308216377160086982
        );                                      
        
        vk.IC[28] = Pairing.G1Point( 
            1508445545112415533291693035630980202584165158204162824942108845767203687242,
            2950132979891328610985103062182171571156521428447965796316487652601614219354
        );                                      
        
        vk.IC[29] = Pairing.G1Point( 
            13367700396071489871853424181132665086718271670076349400019507584162056760030,
            17042164333800567074472821180593428457083824530357266088458459603569984346
        );                                      
        
        vk.IC[30] = Pairing.G1Point( 
            16906353510934497884028252045113276032223164094298867810269553363600239188400,
            1146679118311586720060781184049588237922181637646259599077570590171303991175
        );                                      
        
        vk.IC[31] = Pairing.G1Point( 
            15301558716017764772216180346891098277595838594469486903161465218432412711920,
            6440161521069703248576438838282227541171039308443580352666601253074318051826
        );                                      
        
        vk.IC[32] = Pairing.G1Point( 
            19298898230166436013330515646506131290186830473198149495655757529128845306969,
            3961952868927900885215782234688679936805546356931324453690355296666118786258
        );                                      
        
        vk.IC[33] = Pairing.G1Point( 
            3990229581706754480383146126690436178734384344276920421396615546472491058150,
            10954594483203540690981339694425942134000834573347207670107121861962471233817
        );                                      
        
        vk.IC[34] = Pairing.G1Point( 
            17763412223403675885176513013105553250168869968899890184805718098094982354608,
            6294194172633179312540168919181951911738161780021031270608970748073358134382
        );                                      
        
        vk.IC[35] = Pairing.G1Point( 
            10577838926144365619947541538178538636677716502669266343667771842718713438224,
            14649517283182560000581984080190236355675479793544232931492482238210167226062
        );                                      
        
        vk.IC[36] = Pairing.G1Point( 
            20684497748890214724406459600063432102421472447901988273857284132390980478130,
            6186198867249198177238773519799932431565427267924118163305052377484357896629
        );                                      
        
        vk.IC[37] = Pairing.G1Point( 
            4038467530194133341789640906298881753716503123750954116054484363949904163849,
            9773941539099402218366911982781516774688425033627295778927683080666894961320
        );                                      
        
        vk.IC[38] = Pairing.G1Point( 
            16917997369788502475366898358247053643350697186748282542492979907333496981606,
            2114872759296731339372532201052086111924028719946837119751906835993715721134
        );                                      
        
        vk.IC[39] = Pairing.G1Point( 
            15770457600141770350806948021267617442473372472977032120371309547417716765215,
            4457214352131067830883445377361055376544482218994273146262357491305365716822
        );                                      
        
        vk.IC[40] = Pairing.G1Point( 
            18748691381333929779848537768822802641073912409916988653663394269828749315919,
            14664518882908589938942420988041539273143178288525606760824676192987845518726
        );                                      
        
        vk.IC[41] = Pairing.G1Point( 
            14388472788091908832835076093873982641649131543196395666511571715824614314717,
            1391586242549207877976108865001830283681075314260424117027789636586307780399
        );                                      
        
        vk.IC[42] = Pairing.G1Point( 
            18611003487391984507610944962534542785285404501381236671722352665288100647459,
            21532754665997482360873368575648176983635354973440534733962132407527564207300
        );                                      
        
        vk.IC[43] = Pairing.G1Point( 
            15877557746732443117958252408246700403515647372288605113372874615671990222791,
            14500969825439238288105442314892382789521605839905758911062704437040154399008
        );                                      
        
        vk.IC[44] = Pairing.G1Point( 
            16795712208456815072845545275886234940681542703831768577645735006996402016830,
            6002717050177490876805347952496794749101306545112756120957298046845138929541
        );                                      
        
        vk.IC[45] = Pairing.G1Point( 
            20414139111325881675018477546968163533128444380046463020246146053963511669806,
            13107613032358840572585967113685934571958462824714668948648763658445381018854
        );                                      
        
        vk.IC[46] = Pairing.G1Point( 
            5315994285955903153408235419452976129982738278321349465725624049429198311084,
            16519862601385483748656869136617391685490458924330238656283772654095451703555
        );                                      
        
        vk.IC[47] = Pairing.G1Point( 
            18871570590508860187527331269724481837929944269521794096304132787122411617074,
            10808466822720047137170124686335837488941655337150675858519960203653988977582
        );                                      
        
        vk.IC[48] = Pairing.G1Point( 
            19861567361947652794423731201247971166288094799199698727505993253078188948746,
            9680783802722407755024822418128699101242140804967747210867029507814854264782
        );                                      
        
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length,"verifier-bad-input");
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field,"verifier-gte-snark-scalar-field");
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        if (!Pairing.pairingProd4(
            Pairing.negate(proof.A), proof.B,
            vk.alfa1, vk.beta2,
            vk_x, vk.gamma2,
            proof.C, vk.delta2
        )) return 1;
        return 0;
    }
    /// @return r  bool true if proof is valid
    function verifyProof(
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[48] memory input
        ) public view returns (bool r) {
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
