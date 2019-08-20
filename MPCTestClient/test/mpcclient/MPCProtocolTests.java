package mpcclient;

import mpctestclient.MPCTestClient;
import mpctestclient.MPCRunConfig;
import mpc.Consts;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;


/**
 *
 * @author Petr Svenda
 */
public class MPCProtocolTests {
    
    public MPCProtocolTests() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @AfterMethod
    public void tearDownMethod() throws Exception {
    }
    
    @Test
    void runMPCProtocol_realCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.numPlayers = 4;
        runCfg.thisCardID = 0;
        runCfg.numWholeTestRepeats = 1;
        runCfg.numSingleOpRepeats = 3;
        
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
        
        // Execute 2x
        runCfg.numWholeTestRepeats = 2;
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);

        // Execute 10x
        runCfg.numWholeTestRepeats = 10;
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
    }

    @Test
    void runMPCProtocol_1playerOnly_realCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 1;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
    }

    @Test
    void runMPCProtocol_2playersOnly_realCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 2;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
    }

    @Test
    void runMPCProtocol_3playersOnly_realCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 3;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
    }

    @Test
    void runMPCProtocol_5playersOnly_realCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 5;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
    }

    @Test
    void runMPCProtocol_10playersOnly_realCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 10;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
    }
}
