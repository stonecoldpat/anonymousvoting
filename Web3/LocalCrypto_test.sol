import 'dapple/test.sol'; // virtual "dapple" package imported when `dapple test` is run
import 'LocalCrypto.sol';

// Contract to test access from non-owner accounts.
contract SecondAccount {
    LocalCrypto con;

    uint[2] xG;
    uint[2] yG;
    uint x;

    // Second Person
    function SecondAccount(LocalCrypto _con, uint[2] _xG, uint[2] _yG, uint _x) {
        con = _con;

        xG = _xG;
        yG = _yG;
        x = _x;
    }

    // Submit voting key to Ethereum
    function singleZKP(uint v) returns (bool) {
        uint[4] memory res = con.createZKP(x,v,xG);

        uint[3] memory vG = [res[1], res[2], res[3]];

        return con.verifyZKP(xG, vG, res[0]);
    }

    // Create a YES vote ZKP (in real life this is done via a call.... not a transaction)
    function yes(uint w, uint r, uint d) returns (bool) {
        uint[10] memory res;
        uint[4] memory res2;
        (res, res2) = con.create1outof2ZKPYesVote(xG, yG, w, r, d, x);

        uint[2] memory y = [res[0], res[1]];
        uint[2] memory a1 = [res[2], res[3]];
        uint[2] memory b1 = [res[4], res[5]];
        uint[2] memory a2 = [res[6], res[7]];
        uint[2] memory b2 = [res[8], res[9]];

        return submitVote(res2, y, a1, b1, a2, b2);
    }

    // Create a NO vote ZKP (in real life this is done via a call.... not a transaction)
    function no(uint w, uint r, uint d) returns (bool) {
        uint[10] memory res;
        uint[4] memory res2;

        (res, res2) = con.create1outof2ZKPNoVote(w, r, d, x);

        uint[2] memory y = [res[0], res[1]];
        uint[2] memory a1 = [res[2], res[3]];
        uint[2] memory b1 = [res[4], res[5]];
        uint[2] memory a2 = [res[6], res[7]];
        uint[2] memory b2 = [res[8], res[9]];

        return verify1outof2ZKP(res2, y, a1, b1, a2, b2);
    }

    // Submit vote to Ethereum
    function verify1outof2ZKP(uint[4] params, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) returns (bool) {
        return con.verify1outof2ZKP(params, xG, yG, y, a1, b1, a2, b2);
    }
}

// Deriving from `Test` marks the contract as a test and gives you access to various test helpers.
contract LocalCryptoTest is Test {
    LocalCrypto con;
    Tester proxy_tester;
    SecondAccount A;
    SecondAccount B;
    SecondAccount C;


    // The function called "setUp" with no arguments is
    // called on a fresh instance of this contract before
    // each test. TODO: Document when to put setup logic in
    // setUp vs subclass constructor when writing Test subclasses
    function setUp() {
        con = new LocalCrypto();
        proxy_tester = new Tester();
        proxy_tester._target(con);

        uint x = 100792359988221257522464744073694181557998811287873941943642234039631667801743;
        uint[2] xG = [50011181273477635355105934748199911221235256089199741271573814847024879061899, 71802419974013591686591529237219896883303932349628173412957707346469215125624];
        uint[3] yG = [98038005178408974007512590727651089955354106077095278304532603697039577112780,1801119347122147381158502909947365828020117721497557484744596940174906898953];

        A = new SecondAccount(con, x, xG, yG);

        x = 73684597056470802520640839675442817373247702535850643999083350831860052477001;
        xG = [98038005178408974007512590727651089955354106077095278304532603697039577112780,1801119347122147381158502909947365828020117721497557484744596940174906898953];
        yG = [50011181273477635355105934748199911221235256089199741271573814847024879061899, 71802419974013591686591529237219896883303932349628173412957707346469215125624];
        B = new SecondAccount(con, x, xG, yG);

        x = 106554628258140934843991940734271727557510876833354296893443127816727132563840;
        xG = [33836939586123110014913515630722089627445238026599436014853176202391948851936,112012169245950924685217915153942207169026199800060889564176846526381877678915];
        yG = [50011181273477635355105934748199911221235256089199741271573814847024879061899, 71802419974013591686591529237219896883303932349628173412957707346469215125624];
        C = new SecondAccount(con, x, xG, yG);
    }

    // All voters submit their voting key
    function verifySingleZKP() returns (bool[3]){

        bool[3] memory res;

        uint v = 114941333558360567695678851060848045245826375581561159846926673173053566932687;
        res[0] = A.singleZKP(v);

        v = 28201629513124344311667277080113205903076096953435080012961531044913135153251;
        res[1] = B.singleZKP(v);

        v = 43299936944025232330163985825794231821139305521742829361426928502076888495802;
        res[2] = C.singleZKP(v);

        return res;
    }

    /*// Each user submits their vote.
    function submitVotes() returns (bool[3]) {
        bool[3] memory res;

        // Secrets of ZKP
        uint x = 100792359988221257522464744073694181557998811287873941943642234039631667801743;
        uint w = 25291153222690468941875333155056279849838848426097128907648274067789060660273;
        uint r = 68245514418532339184005707392894217247971162351489303687284716936396921389966;
        uint d = 69359315012171413053095778073649855770462866229159476171746022558873132690484;

        // A will vote 'yes'
        res[0] = A.yesvote(w, r, d, x);

        x = 73684597056470802520640839675442817373247702535850643999083350831860052477001;
        w = 19931063034338608040397431389036375166444930113540469342178236240587103276978;
        r = 87107851681277429609192387607437427289427886314855879969256798426721441034774;
        d = 72164131658574279179250456277220223585855304300653523095781426974019205356799;

        res[1] = B.yesvote(w, r, d, x);

        x = 106554628258140934843991940734271727557510876833354296893443127816727132563840;
        w = 115286148593094397817919321895481582202334666397686766739301438664537464210065;
        r = 815396253592732808824014303738871690433014125945487317500773529831657827334;
        d = 23176707862498098379332945567991301108469279788561094237174439014024723886337;

        res[2] = C.novote(w, r, d, x);

        return res;
    }*/
    // Make sure the coinbase account is the owner
    function testCreatorIsCreator() logs_gas {
        assertEq(address(this), con.owner());
    }

    function testSingleZKP() logs_gas {
        bool[3] res = verifySingleZKP();

        assertTrue(res[0]);
        assertTrue(res[1]);
        assertTrue(res[2]);
    }


    /*// Not all voters have cast their vote.. should throw
    function testCannotSubmitFakeZKP() logs_gas {
        setEligible();
        beginSignUp();
        registerKeys(true, true, true);

        // Private key _x is not the correct 'x' for xG
        uint _x = 10792359988221257522464744073694181557998811287873941943642234039631667801743;
        uint[2] memory xG = [50011181273477635355105934748199911221235256089199741271573814847024879061899, 71802419974013591686591529237219896883303932349628173412957707346469215125624];
        uint v = 114941333558360567695678851060848045245826375581561159846926673173053566932687;

        // Vote should fail. Wrong private key used...
        assertEq(false, A.register(_x,v,xG));
    }

    // Not all voters have cast their vote.. should throw
    function testCannotFakeVote() logs_gas {
        setEligible();
        beginSignUp();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();

        // Changed private key 'x'...
        uint _x = 10792359988221257522464744073694181557998811287873941943642234039631667801743;
        uint w = 25291153222690468941875333155056279849838848426097128907648274067789060660273;
        uint r = 68245514418532339184005707392894217247971162351489303687284716936396921389966;
        uint d = 79359315012171413053095778073649855770462866229159476171746022558873132690484;

        // Vote should fail. Wrong private key used...
        assertEq(false, A.yesvote(w, r, d, _x));
    }*/

}
