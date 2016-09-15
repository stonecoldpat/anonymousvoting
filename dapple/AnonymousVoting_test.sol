import 'dapple/test.sol'; // virtual "dapple" package imported when `dapple test` is run
import 'AnonymousVoting.sol';

// Contract to test access from non-owner accounts.
contract SecondAccount {
    AnonymousVoting con;

    // Second Person
    function SecondAccount(AnonymousVoting _con) {
        con = _con;
    }

    // Submit voting key to Ethereum
    function register(uint x, uint v, uint[2] xG) returns (bool) {
        uint[4] memory res = con.createZKP(x,v,xG);

        uint[3] memory vG = [res[1], res[2], res[3]];

        return con.register(xG, vG, res[0]);
    }

    // Create a YES vote ZKP (in real life this is done via a call.... not a transaction)
    function yesvote(uint w, uint r, uint d, uint x) returns (bool) {
        uint[10] memory res;
        uint[4] memory res2;
        (res, res2) = con.create1outof2ZKPYesVote(w, r, d, x);

        uint[2] memory y = [res[0], res[1]];
        uint[2] memory a1 = [res[2], res[3]];
        uint[2] memory b1 = [res[4], res[5]];
        uint[2] memory a2 = [res[6], res[7]];
        uint[2] memory b2 = [res[8], res[9]];

        return submitVote(res2, y, a1, b1, a2, b2);
    }

    // Create a NO vote ZKP (in real life this is done via a call.... not a transaction)
    function novote(uint w, uint r, uint d, uint x) returns (bool) {
        uint[10] memory res;
        uint[4] memory res2;

        (res, res2) = con.create1outof2ZKPNoVote(w, r, d, x);

        uint[2] memory y = [res[0], res[1]];
        uint[2] memory a1 = [res[2], res[3]];
        uint[2] memory b1 = [res[4], res[5]];
        uint[2] memory a2 = [res[6], res[7]];
        uint[2] memory b2 = [res[8], res[9]];

        return submitVote(res2, y, a1, b1, a2, b2);
    }

    // Submit vote to Ethereum
    function submitVote(uint[4] params, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) returns (bool) {
        return con.submitVote(params, y, a1, b1, a2, b2);
    }
}

// Deriving from `Test` marks the contract as a test and gives you access to various test helpers.
contract AnonymousVotingTest is Test {
    AnonymousVoting con;
    Tester proxy_tester;
    SecondAccount A;
    SecondAccount B;
    SecondAccount C;


    // The function called "setUp" with no arguments is
    // called on a fresh instance of this contract before
    // each test. TODO: Document when to put setup logic in
    // setUp vs subclass constructor when writing Test subclasses
    function setUp() {
        con = new AnonymousVoting();
        proxy_tester = new Tester();
        proxy_tester._target(con);
        A = new SecondAccount(con);
        B = new SecondAccount(con);
        C = new SecondAccount(con);
    }

    // Election Authority updates the white list with our three voters.
    function setEligible() {
        address[] memory test = new address[](3);
        test[0] = address(A);
        test[1] = address(B);
        test[2] = address(C);

        con.setEligible(test);
    }

    // Election Authority dictates that the sign up period has begun.
    function beginSignUp() {
        string memory question = "Should Satoshi Nakamoto reveal his real identity?";
        con.beginSignUp(4, question);
    }

    // All voters submit their voting key
    function registerKeys(bool voter1, bool voter2, bool voter3) returns (bool[3]){

        bool[3] memory res;

        uint x;
        uint[2] memory xG;
        uint v;

        // Should voter 1 register?
        if(voter1) {
            x = 100792359988221257522464744073694181557998811287873941943642234039631667801743;
            xG = [50011181273477635355105934748199911221235256089199741271573814847024879061899, 71802419974013591686591529237219896883303932349628173412957707346469215125624];
            v = 114941333558360567695678851060848045245826375581561159846926673173053566932687;
            res[0] = A.register(x,v,xG);
        }

        // Should voter 2 register?
        if(voter2) {
            x = 73684597056470802520640839675442817373247702535850643999083350831860052477001;
            xG = [98038005178408974007512590727651089955354106077095278304532603697039577112780,1801119347122147381158502909947365828020117721497557484744596940174906898953];
            v = 28201629513124344311667277080113205903076096953435080012961531044913135153251;
            res[1] = B.register(x,v,xG);
        }

        // Should voter 3 register?
        if(voter3) {
            x = 106554628258140934843991940734271727557510876833354296893443127816727132563840;
            xG = [33836939586123110014913515630722089627445238026599436014853176202391948851936,112012169245950924685217915153942207169026199800060889564176846526381877678915];
            v = 43299936944025232330163985825794231821139305521742829361426928502076888495802;
            res[2] = C.register(x,v,xG);
        }

        return res;
    }

    // Election Authority ends the registration phase
    function finishRegistration() {
        con.finishRegistrationPhase();
    }

    // Election Authority computes the voting keys
    function computeKeys() {
        con.computeReconstructedPublicKeys();
    }

    // Each user submits their vote.
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
    }

    function Tally() {
        con.computeTally();
    }

    // Make sure the coinbase account is the owner
    function testCreatorIsCreator() logs_gas {
        assertEq(address(this), con.owner());
    }

    // Set accounts A, B, C as eligible
    function test1SetEligible() logs_gas {
        setEligible();

        // Make sure the owner of the contract is not eligible by default...
        bool res = con.eligible(address(this));
        assertEq(false, res);

        res = con.eligible(address(A));
        assertEq(true, res);

        res = con.eligible(address(B));
        assertEq(true, res);

        res = con.eligible(address(C));
        assertEq(true, res);
    }

    // Test that voters can sign up correctly
    function test2BeginSignUp() logs_gas {
        setEligible();
        beginSignUp();

        // Check timer is set correctly
        assertTrue(con.timer() == 4);
        assertTrue(uint(con.state()) == 1);

        // TODO: Check question is set correctly.
    }

    // Test that voters can submit their key
    function test3SubmitKey() logs_gas {
        setEligible();
        beginSignUp();
        bool[3] memory res = registerKeys(true, true, true);

        // Make sure all three voters submitted their key ok
        assertTrue(res[0]);
        assertTrue(res[1]);
        assertTrue(res[2]);

        // Make sure they are marked as registered to vote
        assertTrue(con.registered(address(A)));
        assertTrue(con.registered(address(B)));
        assertTrue(con.registered(address(C)));

        // Coinbase account should not be registered to vote
        assertFalse(con.registered(address(this)));
    }

    // Test that the Election Authority can finish the registration phase
    function test4FinishRegistration() logs_gas {
        setEligible();
        beginSignUp();
        registerKeys(true, true, true);
        finishRegistration();

        // We should now be in the 'COMPUTE' phase.
        assertTrue(uint(con.state()) == 2);
    }

    // Test that the Election Authority can compute the special voting keys
    function test5ComputeKeys() logs_gas {
        setEligible();
        beginSignUp();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();

        // We should now be in the 'VOTE' phase.
        assertTrue(uint(con.state()) == 3);
    }

    // Submit votes to Ethereum
    function test6SubmitVotes() logs_gas {
        setEligible();
        beginSignUp();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();
        bool[3] memory res = submitVotes();

        // Make sure votes were accepted...
        assertTrue(res[0]);
        assertTrue(res[1]);
        assertTrue(res[2]);

        // Make sure vote has been registered as 'cast'
        assertEq(con.votecast(address(A)), true);
        assertEq(con.votecast(address(B)), true);
        assertEq(con.votecast(address(C)), true);
    }

    // Compute the final tally
    function test7Tally() logs_gas {
        setEligible();
        beginSignUp();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();
        submitVotes();
        Tally();

        // Make sure vote has been registered as 'cast'
        assertEq(con.votecast(address(A)), true);
        assertEq(con.votecast(address(B)), true);
        assertEq(con.votecast(address(C)), true);

        uint yes = con.finaltally(0);
        uint total = con.finaltally(1);

        // Check total number of votes counted...
        assertTrue(yes == 2);

        // Check total number of votes counted...
        assertTrue(total == 3);

        // Make sure we are in the 'finished' state!
        assertTrue(uint(con.state()) == 4);
    }

    // Not all voters have cast their vote.. should throw
    function testThrowCannotTally() logs_gas {
        setEligible();
        beginSignUp();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();

        // Make sure vote has been registered as 'cast'
        assertEq(con.votecast(address(A)), false);
        assertEq(con.votecast(address(B)), false);
        assertEq(con.votecast(address(C)), false);

        Tally();
    }

    // Not all voters have cast their vote.. should throw
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
    }

    // Cannot finish registration phase unless three people have signed up.
    function testCannotEndRegistration() logs_gas {
        setEligible();
        beginSignUp();
        registerKeys(true, true, false);
        finishRegistration();

        // We should still be in the 'signup phase'.
        // Only two people have registered.
        assertTrue(uint(con.state()) == 1);

        // Make sure it is only A and B signed up.
        assertEq(true, con.registered(A));
        assertEq(true, con.registered(B));
        assertEq(false, con.registered(C));
    }

    // Need to test that only 40 people can be eligible
}
