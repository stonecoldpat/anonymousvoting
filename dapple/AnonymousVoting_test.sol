import 'dapple/test.sol'; // virtual "dapple" package imported when `dapple test` is run
import 'AnonymousVoting.sol';
import 'LocalCrypto.sol';

// Contract to test access from non-owner accounts.
contract SecondAccount {
    AnonymousVoting con;
    LocalCrypto crypto;
    uint public x;

    // Second Person
    function SecondAccount(AnonymousVoting _con, LocalCrypto _crypto) {
        con = _con;
        crypto = _crypto;
    }

    // Submit voting key to Ethereum
    function register(uint _x, uint v, uint[2] xG) returns (bool) {
        uint[4] memory res = crypto.createZKP(_x,v,xG);
        uint[3] memory vG = [res[1], res[2], res[3]];
        x = _x;

        return con.register(xG, vG, res[0]);
    }

    // To get over stack issue... seperate creation of ZKP, and submission of vote.
    function createYesZKP(uint[2] xG, uint[2] yG, uint w, uint r, uint d) returns (uint[10] res, uint[4] params){
        (res, params) = crypto.create1outof2ZKPYesVote(xG, yG, w, r, d, x);
    }

    // Should break with new _x
    function createYesZKP(uint[2] xG, uint[2] yG, uint w, uint r, uint d, uint _x) returns (uint[10] res, uint[4] params){
        (res, params) = crypto.create1outof2ZKPYesVote(xG, yG, w, r, d, _x);
    }


    // Create a YES vote ZKP (in real life this is done via a call.... not a transaction)
    // Mostly here to get around call stack issue...
    function yesvote(uint w, uint r, uint d) returns (bool) {
        uint[10] memory res;
        uint[4] memory params;
        uint[2] memory xG;
        uint[2] memory yG;

        (xG, yG,) = con.getVoter();
        (res, params) = createYesZKP(xG, yG, w,r,d);

        uint[2] memory y = [res[0], res[1]];
        uint[2] memory a1 = [res[2], res[3]];
        uint[2] memory b1 = [res[4], res[5]];
        uint[2] memory a2 = [res[6], res[7]];
        uint[2] memory b2 = [res[8], res[9]];

        return con.submitVote(params, y, a1, b1, a2, b2);
    }

    // Change private key... should fail
    function yesvoteNewX(uint w, uint r, uint d) returns (bool) {
        uint[10] memory res;
        uint[4] memory params;
        uint[2] memory xG;
        uint[2] memory yG;

        (xG, yG,) = con.getVoter();
        (res, params) = createYesZKP(xG, yG, w,r,d, 10792359988221257522464744073694181557998811287873941943642234039631667801743);

        uint[2] memory y = [res[0], res[1]];
        uint[2] memory a1 = [res[2], res[3]];
        uint[2] memory b1 = [res[4], res[5]];
        uint[2] memory a2 = [res[6], res[7]];
        uint[2] memory b2 = [res[8], res[9]];

        return con.submitVote(params, y, a1, b1, a2, b2);
    }

    // Create a YES vote ZKP (in real life this is done via a call.... not a transaction)
    // Mostly here to get around call stack issue...
    function yesvotecommit(uint w, uint r, uint d) {
        uint[10] memory res;
        uint[4] memory params;
        uint[2] memory xG;
        uint[2] memory yG;

        (xG, yG,) = con.getVoter();
        (res, params) = createYesZKP(xG, yG, w,r,d);

        uint[2] memory y = [res[0], res[1]];
        uint[2] memory a1 = [res[2], res[3]];
        uint[2] memory b1 = [res[4], res[5]];
        uint[2] memory a2 = [res[6], res[7]];
        uint[2] memory b2 = [res[8], res[9]];

        bytes32 h = crypto.commitToVote(params, xG, yG, y, a1, b1, a2, b2);

        con.submitCommitment(h);
    }


    // Generate the 1 out of 2 ZKP for 'no'.
    // Mostly here to get around call stack issue...
    function createNoZKP(uint[2] xG, uint[2] yG, uint w, uint r, uint d) returns (uint[10] res, uint[4] params) {
        (res, params) = crypto.create1outof2ZKPNoVote(xG, yG, w, r, d, x);
    }

    // Create a NO vote ZKP (in real life this is done via a call.... not a transaction)
    function novote(uint w, uint r, uint d) returns (bool) {
        uint[10] memory res;
        uint[4] memory params;
        uint[2] memory xG;
        uint[2] memory yG;

        (xG, yG,) = con.getVoter();
        (res,params) = createNoZKP(xG, yG, w,r,d);

        uint[2] memory y = [res[0], res[1]];
        uint[2] memory a1 = [res[2], res[3]];
        uint[2] memory b1 = [res[4], res[5]];
        uint[2] memory a2 = [res[6], res[7]];
        uint[2] memory b2 = [res[8], res[9]];

        return con.submitVote(params, y, a1, b1, a2, b2);
    }

    // Create a NO vote ZKP (in real life this is done via a call.... not a transaction)
    function novotecommit(uint w, uint r, uint d) {
        uint[10] memory res;
        uint[4] memory params;
        uint[2] memory xG;
        uint[2] memory yG;

        (xG, yG,) = con.getVoter();
        (res,params) = createNoZKP(xG, yG, w,r,d);

        uint[2] memory y = [res[0], res[1]];
        uint[2] memory a1 = [res[2], res[3]];
        uint[2] memory b1 = [res[4], res[5]];
        uint[2] memory a2 = [res[6], res[7]];
        uint[2] memory b2 = [res[8], res[9]];

        bytes32 h = crypto.commitToVote(params, xG, yG, y, a1, b1, a2, b2);

        con.submitCommitment(h);
    }

    // Submit vote to Ethereum
    function submitVote(uint[4] params, uint[2] y, uint[2] a1, uint[2] b1, uint[2] a2, uint[2] b2) returns (bool) {
        return con.submitVote(params, y, a1, b1, a2, b2);
    }
}

// Deriving from `Test` marks the contract as a test and gives you access to various test helpers.
contract AnonymousVotingTest is Test {
    AnonymousVoting con;
    LocalCrypto crypto;
    Tester proxy_tester;
    SecondAccount A;
    SecondAccount B;
    SecondAccount C;

    event Debug(bool eligible, bool registered, bool votecast);
    event GetVoter(uint xG_x, uint xG_y, uint yG_x, uint yG_y);
    event DebugInts(uint x, uint y, uint z);

    // The function called "setUp" with no arguments is
    // called on a fresh instance of this contract before
    // each test. TODO: Document when to put setup logic in
    // setUp vs subclass constructor when writing Test subclasses
    function setUp() {
        con = new AnonymousVoting();
        crypto = new LocalCrypto();
        proxy_tester = new Tester();
        proxy_tester._target(con);
        A = new SecondAccount(con, crypto);
        B = new SecondAccount(con, crypto);
        C = new SecondAccount(con, crypto);
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
    function beginSignUp(bool commitment, uint finishSignup, uint endSignup, uint endComputation, uint endCommitment, uint endVoting, uint endRefund, uint deposit) {
        string memory question = "Should Satoshi Nakamoto reveal his real identity?";

        setEligible();
        con.beginSignUp(question, commitment, finishSignup, endSignup, endComputation, endCommitment, endVoting, endRefund, deposit);
    }

    // Easy function to begin election without commitment
    function beginSignupWithoutCommitment() {
        uint gap = con.gap();
        uint multiplier = con.refundgapmultiplier();
        uint finishSignup = 2;
        uint endSignup = finishSignup + gap;
        uint endComputation = endSignup + gap;
        uint endVoting = endComputation + gap;
        uint endRefund = endVoting + (gap*multiplier);
        string memory question = "Should Satoshi Nakamoto reveal his real identity?";
        con.beginSignUp(question, false, finishSignup, endSignup, endComputation, 0, endVoting, endRefund, 0);
    }

    // Easy function to begin election with commitment
    function beginSignupWithCommitment() {
        uint gap = con.gap();
        uint multiplier = con.refundgapmultiplier();
        uint finishSignup = 2;
        uint endSignup = finishSignup + gap;
        uint endComputation = endSignup + gap;
        uint endCommitment = endComputation + gap;
        uint endVoting = endCommitment + gap;
        uint endRefund = endVoting + (gap*multiplier);
        string memory question = "Should Satoshi Nakamoto reveal his real identity?";
        con.beginSignUp(question, true, finishSignup, endSignup, endComputation, endCommitment, endVoting, endRefund, 0);
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
        uint w = 25291153222690468941875333155056279849838848426097128907648274067789060660273;
        uint r = 68245514418532339184005707392894217247971162351489303687284716936396921389966;
        uint d = 69359315012171413053095778073649855770462866229159476171746022558873132690484;

        // A will vote 'yes'
        res[0] = A.yesvote(w, r, d);

        w = 19931063034338608040397431389036375166444930113540469342178236240587103276978;
        r = 87107851681277429609192387607437427289427886314855879969256798426721441034774;
        d = 72164131658574279179250456277220223585855304300653523095781426974019205356799;

        res[1] = B.yesvote(w, r, d);

        w = 115286148593094397817919321895481582202334666397686766739301438664537464210065;
        r = 815396253592732808824014303738871690433014125945487317500773529831657827334;
        d = 23176707862498098379332945567991301108469279788561094237174439014024723886337;

        res[2] = C.novote(w, r, d);

        return res;
    }

    // Each user submits their vote.
    function submitCommitments() {
        bool[3] memory res;

        // Secrets of ZKP
        uint w = 25291153222690468941875333155056279849838848426097128907648274067789060660273;
        uint r = 68245514418532339184005707392894217247971162351489303687284716936396921389966;
        uint d = 69359315012171413053095778073649855770462866229159476171746022558873132690484;

        // A will vote 'yes'
        A.yesvotecommit(w, r, d);

        w = 19931063034338608040397431389036375166444930113540469342178236240587103276978;
        r = 87107851681277429609192387607437427289427886314855879969256798426721441034774;
        d = 72164131658574279179250456277220223585855304300653523095781426974019205356799;

        B.yesvotecommit(w, r, d);

        w = 115286148593094397817919321895481582202334666397686766739301438664537464210065;
        r = 815396253592732808824014303738871690433014125945487317500773529831657827334;
        d = 23176707862498098379332945567991301108469279788561094237174439014024723886337;

        C.novotecommit(w, r, d);
    }

    function Tally() {
        con.computeTally();
    }

    function testBeginSetUpBadBeginSignup() {
      setEligible();

      uint gap = con.gap();
      uint finishSignup = 1916006400;
      uint endSignup = finishSignup + gap - 1;
      uint endComputation = endSignup + gap;
      uint endCommitment = endComputation + gap;
      uint endVoting = endCommitment + gap;
      uint endRefund = endVoting + gap;

      beginSignUp(true, finishSignup, endSignup, endComputation, endCommitment, endVoting, endRefund, 0);

      // We should not have changed state.
      assertTrue(uint(con.state()) == 0);
    }

    function testBeginSetUpBadEndComputation() {
      setEligible();

      uint gap = con.gap();
      uint finishSignup = 1916006400;
      uint endSignup = finishSignup + gap;
      uint endComputation = endSignup + gap - 1;
      uint endCommitment = endComputation + gap;
      uint endVoting = endCommitment + gap;
      uint endRefund = endVoting + gap;
      beginSignUp(true, finishSignup, endSignup, endComputation, endCommitment, endVoting, endRefund, 0);

      // We should not have changed state.
      assertTrue(uint(con.state()) == 0);
    }

    function testBeginSetUpBadEndCommitment() {
      setEligible();

      uint gap = con.gap();
      uint finishSignup = 1916006400;
      uint endSignup = finishSignup + gap;
      uint endComputation = endSignup + gap;
      uint endCommitment = endComputation + gap - 1;
      uint endVoting = endCommitment + gap;
      uint endRefund = endVoting + gap;
      beginSignUp(true, finishSignup, endSignup, endComputation, endCommitment, endVoting, endRefund, 0);

      // We should not have changed state.
      assertTrue(uint(con.state()) == 0);
    }

    function testBeginSetUpBadEndVoting() {
      setEligible();

      uint gap = con.gap();
      uint finishSignup = 1916006400;
      uint endSignup = finishSignup + gap;
      uint endComputation = endSignup + gap;
      uint endCommitment = endComputation + gap;
      uint endVoting = endCommitment + gap - 1;
      uint endRefund = endVoting + gap;
      beginSignUp(true, finishSignup, endSignup, endComputation, endCommitment, endVoting, endRefund, 0);

      // We should not have changed state.
      assertTrue(uint(con.state()) == 0);
    }

    function testBeginSetUpBadEndVotingWithoutCommitmentPhase() {
      setEligible();

      uint gap = con.gap();
      uint finishSignup = 1916006400;
      uint endSignup = finishSignup + gap;
      uint endComputation = endSignup + gap;
      uint endCommitment = 0;
      uint endVoting = endComputation + gap - 1;
      uint endRefund = endVoting + gap;
      beginSignUp(false, finishSignup, endSignup, endComputation, endCommitment, endVoting, endRefund, 0);

      // We should not have changed state.
      assertTrue(uint(con.state()) == 0);
    }

    function testBeginSetUpWithCommitment() {
        setEligible();
        beginSignupWithCommitment();
        assertTrue(uint(con.state()) == 1);
        assertTrue(con.finishSignupPhase() == 2);
        assertTrue(con.endSignupPhase() == 3);
        assertTrue(con.endComputationPhase() == 4);
        assertTrue(con.endCommitmentPhase() == 5);
        assertTrue(con.endVotingPhase() == 6);
        assertTrue(con.endRefundPhase() == 7);
    }

    // Test that voters can sign up correctly
    function testBeginSignUpWithoutCommitment() {
        setEligible();
        beginSignupWithoutCommitment();
        assertTrue(uint(con.state()) == 1);
        assertTrue(con.finishSignupPhase() == 2);
        assertTrue(con.endSignupPhase() == 3);
        assertTrue(con.endComputationPhase() == 4);
        assertTrue(con.endVotingPhase() == 5);
        assertTrue(con.endRefundPhase() == 6);
    }


    function testBeginSignUpWithoutCommitmentreaterThanGap() {
      setEligible();

      uint gap = con.gap();
      uint gapIncrease = 1000;
      uint finishSignup = 1916006400;
      uint endSignup = finishSignup + gap + gapIncrease;
      uint endComputation = endSignup + gap + gapIncrease;
      uint endVoting = endComputation + gap + gapIncrease;
      uint endRefund = endVoting + gap + gapIncrease;
      beginSignUp(false, finishSignup, endSignup, endComputation, 0, endVoting, endRefund, 0);

      // We should not have changed state.
      assertTrue(uint(con.state()) == 1);
      assertTrue(con.finishSignupPhase() == finishSignup);
      assertTrue(con.endSignupPhase() == endSignup);
      assertTrue(con.endComputationPhase() == endComputation);
      assertTrue(con.endVotingPhase() == endVoting);
      assertTrue(con.endRefundPhase() == endRefund);
    }

    function testBeginSignUpWithCommitmentreaterThanGap() {
      setEligible();

      uint gap = con.gap();
      uint gapIncrease = 1000;
      uint finishSignup = 1916006400;
      uint endSignup = finishSignup + gap + gapIncrease;
      uint endComputation = endSignup + gap + gapIncrease;
      uint endCommitment = endComputation + gap + gapIncrease;
      uint endVoting = endCommitment + gap + gapIncrease;
      uint endRefund = endVoting + gap + gapIncrease;
      beginSignUp(true, finishSignup, endSignup, endComputation, endCommitment, endVoting, endRefund, 0);

      // We should not have changed state.
      assertTrue(uint(con.state()) == 1);
      assertTrue(con.finishSignupPhase() == finishSignup);
      assertTrue(con.endSignupPhase() == endSignup);
      assertTrue(con.endComputationPhase() == endComputation);
      assertTrue(con.endCommitmentPhase() == endCommitment);
      assertTrue(con.endVotingPhase() == endVoting);
      assertTrue(con.endRefundPhase() == endRefund);
    }

    // Make sure the coinbase account is the owner
    function testCreatorIsCreator() logs_gas {
        assertEq(address(this), con.owner());
    }

    // Set accounts A, B, C as eligible
    function testSetEligible() logs_gas {
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

    // Test that voters can submit their key
    function testSubmitKey() logs_gas {
        setEligible();
        beginSignupWithoutCommitment();
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
    function testFinishRegistration() logs_gas {
        setEligible();
        beginSignupWithoutCommitment();
        registerKeys(true, true, true);
        finishRegistration();

        // We should now be in the 'COMPUTE' phase.
        assertTrue(uint(con.state()) == 2);
    }

    // Test that the Election Authority can compute the special voting keys
    function testComputeKeys() logs_gas {
        setEligible();
        beginSignupWithoutCommitment();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();

        // We should now be in the 'VOTE' phase.
        assertTrue(uint(con.state()) == 4);
    }

    // Submit votes to Ethereum
    function testSubmitVotes() logs_gas {
        setEligible();
        beginSignupWithoutCommitment();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();
        assertTrue(uint(con.state()) == 4);

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

    // Submit votes to Ethereum
    function testSubmitCommitments() logs_gas {
        setEligible();
        beginSignupWithCommitment();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();
        assertTrue(uint(con.state()) == 3);
        submitCommitments();
        assertTrue(uint(con.state()) == 4);

        // Verify that the commitments where accepted..
        assertTrue(con.commitment(address(A)));
        assertTrue(con.commitment(address(B)));
        assertTrue(con.commitment(address(C)));
    }

    // Submit votes to Ethereum
    function testRevealCommitments() logs_gas {
        setEligible();
        beginSignupWithCommitment();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();
        assertTrue(uint(con.state()) == 3);
        submitCommitments();
        assertTrue(uint(con.state()) == 4);
        submitVotes();
        assertEq(con.votecast(address(A)), true);
        assertEq(con.votecast(address(B)), true);
        assertEq(con.votecast(address(C)), true);
    }

    // Submit votes to Ethereum
    function testCommitRevealTally() logs_gas {
        setEligible();
        beginSignupWithCommitment();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();
        assertTrue(uint(con.state()) == 3);
        submitCommitments();
        assertTrue(uint(con.state()) == 4);
        submitVotes();
        Tally();

        uint yes = con.finaltally(0);
        uint total = con.finaltally(1);

        // Check total number of votes counted...
        assertTrue(yes == 2);

        // Check total number of votes counted...
        assertTrue(total == 3);

        // Make sure we are in the 'finished' state!
        assertTrue(uint(con.state()) == 5);
    }

    // Compute the final tally
    function testTally() logs_gas {
        setEligible();
        beginSignupWithoutCommitment();
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
        assertTrue(uint(con.state()) == 5);
    }

    // Not all voters have cast their vote.. should throw
    function testThrowCannotTally() logs_gas {
        setEligible();
        beginSignupWithoutCommitment();
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
        beginSignupWithoutCommitment();
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
        beginSignupWithoutCommitment();
        registerKeys(true, true, true);
        finishRegistration();
        computeKeys();

        // Changed private key 'x'...
        uint w = 25291153222690468941875333155056279849838848426097128907648274067789060660273;
        uint r = 68245514418532339184005707392894217247971162351489303687284716936396921389966;
        uint d = 79359315012171413053095778073649855770462866229159476171746022558873132690484;

        // Vote should fail. Wrong private key used...
        assertEq(false, A.yesvoteNewX(w, r, d));
    }

    // Cannot finish registration phase unless three people have signed up.
    function testCannotEndRegistration() logs_gas {
        setEligible();
        beginSignupWithoutCommitment();
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
}
