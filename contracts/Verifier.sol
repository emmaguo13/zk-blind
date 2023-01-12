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
            [7562558195140180531076437653165710309938919622934042363194905502617330204551,
             14531982116431662363316039073800297008469924465484923646947970482134007687649],
            [12776510976355085043817397944833387574208046541961315432661415053657541275888,
             21321179106000063415414991282723846345523555859879395957457257281969504755776]
        );
        vk.IC = new Pairing.G1Point[](49);
        
        vk.IC[0] = Pairing.G1Point( 
            19964839195415614214645660447622226023341589709129193368096683200653781088363,
            16037002266802664819937495433488128659868828167431776325730251422503440575652
        );                                      
        
        vk.IC[1] = Pairing.G1Point( 
            12762810175867959967979756581484548433889481112474894496191420191702858759254,
            20117476781882852719041218012955967789774335871824630273887996598246066621002
        );                                      
        
        vk.IC[2] = Pairing.G1Point( 
            2252480046004851920146760256670960946216304243266252821738061808370575102739,
            8990090422992628768154313031169441577982500914731296245385279456746048771363
        );                                      
        
        vk.IC[3] = Pairing.G1Point( 
            4305632796424978313387951022798275809253989744455423243562223524718481996807,
            14059454625710234496929918173703883488661036513792478566923704856010912272662
        );                                      
        
        vk.IC[4] = Pairing.G1Point( 
            12110396767606520145971672294183871587592554555031166330782959893071867238671,
            11341344455035421824681646019995899305133254924982394677233611646587709515646
        );                                      
        
        vk.IC[5] = Pairing.G1Point( 
            19627493335618694138172546037142779393507543155041489321888690295546210427913,
            971822280590922689223375579346589051610178167895081185884925698804207407168
        );                                      
        
        vk.IC[6] = Pairing.G1Point( 
            6133300864919786639604905032944231078894301963774944637616134804306801260129,
            2556411213788503864016560861262060720120271897147204111406108239574528168102
        );                                      
        
        vk.IC[7] = Pairing.G1Point( 
            20844758386899721606571734833403533185578633422280872702135157147887130036599,
            14178464109842394172348940819547048242747819485780830669719152382502234398497
        );                                      
        
        vk.IC[8] = Pairing.G1Point( 
            2157403598739251934391142953922853867357494529776847056090528565436516630936,
            627985493082942195652553859838132478232820714405892512954001573081335335463
        );                                      
        
        vk.IC[9] = Pairing.G1Point( 
            3939773991371518718769716166938776124670828129509419237716858354091960865530,
            1079378424781340050840453558597593722394084489919549425404663249157383290603
        );                                      
        
        vk.IC[10] = Pairing.G1Point( 
            8392975527107585220939319749787861235708952581346523640319600589650138305527,
            18146348228994322886314443739751224762553161398459488601565333081568492649925
        );                                      
        
        vk.IC[11] = Pairing.G1Point( 
            5831448375356139768552159100848800203302001172226306459704688070126368420850,
            14402407798859062586805458168193841096335481632388119327367066180283160099159
        );                                      
        
        vk.IC[12] = Pairing.G1Point( 
            12091719641578185784089691122197253825906838114861585652426811947974122941954,
            8395583572769652584117163532460678520057757138448382982677411413472654590305
        );                                      
        
        vk.IC[13] = Pairing.G1Point( 
            20568228454618409448695947623347607685802058824581275639717669729370210480106,
            9817083740156933357020401059947000529074421142281734158574541060591924842908
        );                                      
        
        vk.IC[14] = Pairing.G1Point( 
            11523570708680836488140958565505841080580060144802843452194335296889135513359,
            12343840352249369272694723644163887857692220955084856161307842964398779079741
        );                                      
        
        vk.IC[15] = Pairing.G1Point( 
            3691343342001308360050713038847542987501299539178115393200252928161295251965,
            13270619329064401131353048031595260418305710497419530918552460251342564644404
        );                                      
        
        vk.IC[16] = Pairing.G1Point( 
            6618454485737597302587771511157825315969930326872756938143836710866762090331,
            16396979185163227092690800003882837088778513174812195045155125811497642054583
        );                                      
        
        vk.IC[17] = Pairing.G1Point( 
            12713847784598856792957777773785115373534236410618896702280018605403920606256,
            21518071726037477329288214584289511947470198071862849363970133300295560828324
        );                                      
        
        vk.IC[18] = Pairing.G1Point( 
            6316451378407290658662614195950366642691874898159799864156225984254742302707,
            3316804922494743423761339775999463946102643242065777548634337578977434504702
        );                                      
        
        vk.IC[19] = Pairing.G1Point( 
            4303723770643870566139101386028170752345369309880737225638885804982786075271,
            7275298507115369102284091849883543205428313568266517546574840040141476135447
        );                                      
        
        vk.IC[20] = Pairing.G1Point( 
            9993749848427444834561419580090305347412942341974704427328509144614950820744,
            12646134359208342688550588902371473420682996971071356171941801628201613081321
        );                                      
        
        vk.IC[21] = Pairing.G1Point( 
            20638011998798903657065147255079770121057837366245733231132338826211784149812,
            6222220924803775612389096676333141641118069567056079986567036421721790916413
        );                                      
        
        vk.IC[22] = Pairing.G1Point( 
            6624858467381901211122872081385849767321998151048112262814049842237486142409,
            2008198651603120977667878820934805225922657883259038514895708425756653917655
        );                                      
        
        vk.IC[23] = Pairing.G1Point( 
            12405291842503842978076782610491651254343477057956974080215005920216348522092,
            8021391267463532089270370687617551866718855068682826554570272236662035404149
        );                                      
        
        vk.IC[24] = Pairing.G1Point( 
            21511588751434973715545017469600569788009151199285829605300923142341400966138,
            20725687958588456538186742312562444259675214517376054036712557041146995853753
        );                                      
        
        vk.IC[25] = Pairing.G1Point( 
            20839797645507867017699796468941190977982555257930298790593507117665252969998,
            4186970729118015640391444460239448756726941232013792247631190896378109876702
        );                                      
        
        vk.IC[26] = Pairing.G1Point( 
            18852623326906639842946068408664978482858053256691418153685925018047945845304,
            15983986199590053269009582595898183813608668599949888567754798083132407775481
        );                                      
        
        vk.IC[27] = Pairing.G1Point( 
            2329108696300202658168626110594379715926613647969909277898824655796028948903,
            8826698544065642985407164503926247946944303874815726455257563722714912746312
        );                                      
        
        vk.IC[28] = Pairing.G1Point( 
            10454750735930038722122626472119101912672213734504997022811063164344636120694,
            6848201660300195568565547667285252085516537344842093220303569622789669069025
        );                                      
        
        vk.IC[29] = Pairing.G1Point( 
            16233424711925686341783030932522171783578130217938450230307714676668036822113,
            10487326692814647668931279003142274810057248331644678010742282773450714409623
        );                                      
        
        vk.IC[30] = Pairing.G1Point( 
            21127792649611094574703626337028964410442221153536492614277754349913267222384,
            2136013515312369994189176269272648244704719987439019442140299525391641999967
        );                                      
        
        vk.IC[31] = Pairing.G1Point( 
            20810282286039036262199577523030208332600611303629892180338960668195366851353,
            12074174273176156849722171390138704371592009634996135177369887699929948473530
        );                                      
        
        vk.IC[32] = Pairing.G1Point( 
            7834211874300028634386979478575412816468607333618013411945791735030196649573,
            14635457947214472605500054683890133138020619923117142372892213666599355373371
        );                                      
        
        vk.IC[33] = Pairing.G1Point( 
            481658654592710695073297378015491788631890886842103213266220438280156043869,
            5091805013829986023712533385070223892734312830851512520796638525768254251149
        );                                      
        
        vk.IC[34] = Pairing.G1Point( 
            2944994566978157130578781852001122527553672389609878313699545736108031682760,
            16967101461923913116533157907867066402634839641469852477985970848687500137667
        );                                      
        
        vk.IC[35] = Pairing.G1Point( 
            10124036066628271254446754300483202498643981091970522696265927229262494008840,
            11957629092943688876023370371100921769577400875638007977302020604401934843110
        );                                      
        
        vk.IC[36] = Pairing.G1Point( 
            652545329142878936262555788808785780864656181187870650254974725818057925610,
            3236436642483785076292275258957528294603959308219961642144963512264127178416
        );                                      
        
        vk.IC[37] = Pairing.G1Point( 
            13411244704949967004563390784035129033360553371683732197836204211314889607552,
            5119782257360084687470204953477266337405835233373887603397239205397063090139
        );                                      
        
        vk.IC[38] = Pairing.G1Point( 
            18125673705753234996059781212936613201984286264212936535049914747266474344037,
            6580208148395871161457582304419841298570896796060701622596030005000687952711
        );                                      
        
        vk.IC[39] = Pairing.G1Point( 
            9307823195711801717485834436565017177401001327811613673387567118510760262152,
            21719277737318634312526949643557615583409223691515242049904383442141669194669
        );                                      
        
        vk.IC[40] = Pairing.G1Point( 
            13071355867834140210013469501865162166203313143069585937840937844965459304168,
            14939494230998221934832126022073415134101788189540514832714902066656289986190
        );                                      
        
        vk.IC[41] = Pairing.G1Point( 
            2638457122115633482161141010468776093187556575904543325145231464284021180242,
            20008359036985310670021410964931491858961835837023897669506636015543795285625
        );                                      
        
        vk.IC[42] = Pairing.G1Point( 
            19734196782900811239332017310838665239718858218435430278534762444895575366118,
            21202043488605772022325671127526956704387850841165526228675530902095729561624
        );                                      
        
        vk.IC[43] = Pairing.G1Point( 
            20215956461205752268606395311928975633900245731844154692378185591046894981855,
            7858677188494369613805032398304925524666558672357991444433120738583008885045
        );                                      
        
        vk.IC[44] = Pairing.G1Point( 
            13747500567772213356467917894303870989313669826014649225271235240039118192419,
            12758160557983548482531735007704287442726367340345256617989854727258629437698
        );                                      
        
        vk.IC[45] = Pairing.G1Point( 
            1839943726312293503710271345983323903721751195971294817157936937194125921007,
            1889225093552653237185391872337038450924231965605473495349888018278025752442
        );                                      
        
        vk.IC[46] = Pairing.G1Point( 
            11066970842220233103025978733691843070559405329350666776877192035367341720202,
            18290100461540947642768751179304296747228090357835728768079388163217195025565
        );                                      
        
        vk.IC[47] = Pairing.G1Point( 
            17552136295079513990291444436569481789135074765635809498087565990390507824964,
            16708296923153294733790671129880815452566081222769190684857601186872333364649
        );                                      
        
        vk.IC[48] = Pairing.G1Point( 
            21634328403925330808441003803428400332830718926172421626003706964764959613985,
            7829913748683951996966966822020823818510709230164970041360431509009972441875
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
