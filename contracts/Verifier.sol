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
            [4835648955079222026656198166765608729104858565613626282635064688772572336095,
             17237224482274224995166076321882841466281156092600101802841532347513422629396],
            [19470693571854987206324774167265025917916781840656062849526183316744878911614,
             12012581634867220949220887510121731425148050787351186134540068276591275006983]
        );
        vk.IC = new Pairing.G1Point[](49);
        
        vk.IC[0] = Pairing.G1Point( 
            20051464613832018473613601632902798456881313277137296835590703978655949283329,
            16090112617019933608926865831433240197753068770303965576646141973589354466399
        );                                      
        
        vk.IC[1] = Pairing.G1Point( 
            16594065687435924654865878625155651492359399509266735110731060373944030591396,
            8777501682656180435191518167410071523955840263898184052454580517630956607464
        );                                      
        
        vk.IC[2] = Pairing.G1Point( 
            14286385436945299263338456187447638607380173098671601342364370551787298746506,
            9607550463211609795008501885047820042747805398684347258147171141252895802791
        );                                      
        
        vk.IC[3] = Pairing.G1Point( 
            2655237033934732674266980291158039364255552187069061167190079808409780353807,
            17454698445648660207432570750988839927261073252143454635063982835846885571920
        );                                      
        
        vk.IC[4] = Pairing.G1Point( 
            17606471961137793990334675813835439084121469428324804190290692897228856334231,
            8494096185041901455714840198927875952578099442454730430086307127622198474497
        );                                      
        
        vk.IC[5] = Pairing.G1Point( 
            11774855955194766907577144625402407727713014562503765716333569307482736635073,
            21226255923667511245459880146129864381655967035745564699131199715047610458210
        );                                      
        
        vk.IC[6] = Pairing.G1Point( 
            16247111992235412074550076122970002811067452566756017525999704777411636020544,
            19189945066092223653893641525177754472296449269465478670079721488019663240918
        );                                      
        
        vk.IC[7] = Pairing.G1Point( 
            17633557047584648732639279618574500689357783540848711607769439109818718933877,
            756395437726194665546234180527130377110806363690904305196048466347177389752
        );                                      
        
        vk.IC[8] = Pairing.G1Point( 
            6145056205678117730782260681499997473657490283229513926778414555978043486544,
            10707296977886679288700757092363858516868125249626529949806850279472383381124
        );                                      
        
        vk.IC[9] = Pairing.G1Point( 
            4815782861729759656105798969328964075413228201767809315639790674961211725674,
            9947423291903669439682253490172134232062015934911888411635280649760696934271
        );                                      
        
        vk.IC[10] = Pairing.G1Point( 
            8329111784876154298102315734112821057711348001372540239082447644779747371580,
            5137362322333281616039484953977936568199083379008756006404978626474839769944
        );                                      
        
        vk.IC[11] = Pairing.G1Point( 
            20640848538307561025017582126011824412536340482344949046745111776387806827573,
            12042609779614055635333438721954964730695926282092258548714492509908749880349
        );                                      
        
        vk.IC[12] = Pairing.G1Point( 
            5695097653020321006748944118712969260588725749465570592641778119403215233605,
            16240597833258019538311295509882011818023534086245951061913923759787521148941
        );                                      
        
        vk.IC[13] = Pairing.G1Point( 
            5935256643766362514509190480643810712528429135344201470730666566006200104944,
            6989634220744016616542628376982158269286357753144097452313999975069711871459
        );                                      
        
        vk.IC[14] = Pairing.G1Point( 
            20574350138836697695575278140686310933388056827198802628502764559727999160628,
            4532442781497525142700037819544037378690403690948427826877821543488465330694
        );                                      
        
        vk.IC[15] = Pairing.G1Point( 
            8311329429416081767490306103180800442937592609933503337536476731631705367460,
            12281349839511047388098030732696707309728127078281778891363717070622009636980
        );                                      
        
        vk.IC[16] = Pairing.G1Point( 
            11354537613494951931411463831291570154893601291172421176005539457252278767747,
            6853704887474408986840712047136509395701666200980895886281758696747705892841
        );                                      
        
        vk.IC[17] = Pairing.G1Point( 
            2816264268285907328977080362526769182137353792378119048546050209932196774184,
            13560115045568438255434928962489210612257676147183087494903977900989496668566
        );                                      
        
        vk.IC[18] = Pairing.G1Point( 
            15828752148913699453453947944720115533548743933867383377329256326827589863096,
            12310803057659078956140035808413104000348233217026572818594519575691335080894
        );                                      
        
        vk.IC[19] = Pairing.G1Point( 
            17466829272695315868321017926119718582563557356421739884892228275551102638494,
            5304158563583196073288422587099769168129339413242463812996754946091532044557
        );                                      
        
        vk.IC[20] = Pairing.G1Point( 
            9650440595855773755347442563220275756559453032538750693754532824674894742928,
            7411556275045677180538357132624396463675600734654226240130503855884532408589
        );                                      
        
        vk.IC[21] = Pairing.G1Point( 
            2108311632598860687214971751436403342597330038045377476358758719922274522067,
            5813341496590180323891247702369070622028267939326627757054650833090182309069
        );                                      
        
        vk.IC[22] = Pairing.G1Point( 
            5643690462683728452143354715472508830583517731127008705194227194222139340499,
            6750460562596135294604840266344580842260650665182279404874788486115490582278
        );                                      
        
        vk.IC[23] = Pairing.G1Point( 
            9400134096429966315773273340091956309707757440861932276635970087706247367327,
            14206405686055532100106996944787387747890228284895615883982559928630899486048
        );                                      
        
        vk.IC[24] = Pairing.G1Point( 
            16653802711372137194970244925504406633443742144127172078029477032036347179234,
            17977812549979077980194834612479061873639360645327205400806607731051012136340
        );                                      
        
        vk.IC[25] = Pairing.G1Point( 
            3786784581308143142084597359779034285282421766148983270856025754792114291804,
            18952166226218515857438320696216806070793831757388805409034119652663094087702
        );                                      
        
        vk.IC[26] = Pairing.G1Point( 
            14898743666218159787871353195490045412130907407532310801541792478819654074262,
            18691424271331352444667161168327539301768488042931071467120061907531388821679
        );                                      
        
        vk.IC[27] = Pairing.G1Point( 
            14400531747369905272225360028633237483907176737657841107895133620680860192498,
            17528340721884061166414346504331238590185572973608358336543098014524587821915
        );                                      
        
        vk.IC[28] = Pairing.G1Point( 
            20178770784780265524350732700816461212054993259400962406974990031813114986233,
            11181014924486390465422873926914602829173930857302754200039266036897548138119
        );                                      
        
        vk.IC[29] = Pairing.G1Point( 
            4523922323556894588717116648510979667770721702476165321638387818025474062223,
            17665243372249271342922658802416586465705703400559248387738414158274468570800
        );                                      
        
        vk.IC[30] = Pairing.G1Point( 
            3320328333717901043365495388160116059160222371389349458559536349179232117884,
            1013630358328159509419719057170054172128766804255485826532625616211334757217
        );                                      
        
        vk.IC[31] = Pairing.G1Point( 
            2654011088141787046843274232114972795001629541976579441599155464475262590423,
            17269311188399043466277225018324359524655272994294116564942103175000749627165
        );                                      
        
        vk.IC[32] = Pairing.G1Point( 
            4419704980933235637276356821887608135834736331288635796743540569908299877563,
            19807584864084925497619841369152253562851633392007214845118054456634267898889
        );                                      
        
        vk.IC[33] = Pairing.G1Point( 
            221676072228297962153257541221769678795822670451600095929827726570286067016,
            20675739863196909614124530901157113293252136611547621959035283009282779167355
        );                                      
        
        vk.IC[34] = Pairing.G1Point( 
            14685141917723657889085026260810093282567357819748191600207876659185918904133,
            20612250083054587238328937276505702831400178506467703988422097752768861707038
        );                                      
        
        vk.IC[35] = Pairing.G1Point( 
            9507836445429096222504076402435790200611310342690132417988952807384851479523,
            2780121248716134030989648290049674536342743543701168299162402391360481669906
        );                                      
        
        vk.IC[36] = Pairing.G1Point( 
            3545461205364236761714769111431947843777280714361044434104989575732208238898,
            10785403459046557962515763006720932305034596308610222414812690657404085676938
        );                                      
        
        vk.IC[37] = Pairing.G1Point( 
            9232953808555129393556443960450953304547469533326332709616055390449973762490,
            16656397039821840360877582320701933981720843729236435546887791901492687318673
        );                                      
        
        vk.IC[38] = Pairing.G1Point( 
            1700194950777379212680115965329060276021739914001135438238428050566810392149,
            12375279976963197141774158460538301291174575563026846628227575040211759875503
        );                                      
        
        vk.IC[39] = Pairing.G1Point( 
            7627919916498174817757481556811581126282165769471123813322012392419373790751,
            13031984877215392952557114131742937345402829371744745585727840392871218510241
        );                                      
        
        vk.IC[40] = Pairing.G1Point( 
            3502981144136220387923444356484307163027828205152804736118632503469913226441,
            9771525273534407287930735228719817928822173516820706132693746150139634687127
        );                                      
        
        vk.IC[41] = Pairing.G1Point( 
            339433087758030381944557586328849786930464535948798077151658304741947058091,
            8330626385959795254179847348685712765262705333836175243275850007433582924016
        );                                      
        
        vk.IC[42] = Pairing.G1Point( 
            16313484605049439753828233817226668606336203734444516654727361318262215386484,
            10524644180955980612957107870814854592659955887049159859228580666485816879380
        );                                      
        
        vk.IC[43] = Pairing.G1Point( 
            968375776478640621266146700607948327111799980533614321454129944145921990980,
            21028850972927344379345707941159675470252083211603334516151696751476427752109
        );                                      
        
        vk.IC[44] = Pairing.G1Point( 
            12172656527692494643443062646233847946899534333340121163032872675131410114759,
            1912904585255049326716016019132514111624507703316814600771891988904794298825
        );                                      
        
        vk.IC[45] = Pairing.G1Point( 
            6569591543816784679163440029152935761943952306771099913325887254703816053712,
            2471664623714728536803895109257718332839974662608641964879977716047584104772
        );                                      
        
        vk.IC[46] = Pairing.G1Point( 
            3097184249509683680110925104098728511337888281971900760933623105331118204387,
            5471291820090258258474840996562928587255715982031040613282722496876803399711
        );                                      
        
        vk.IC[47] = Pairing.G1Point( 
            17013959490667406561941083445652700120230492883152742551337661239805605544139,
            21740261757942444074674953393795853665820464720318553256839771926476573960743
        );                                      
        
        vk.IC[48] = Pairing.G1Point( 
            13789463001701720068644481780139018623810535774918268530883147972470687516235,
            7909284388362215423874954942356576175208405895570147858713181486416954246620
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
