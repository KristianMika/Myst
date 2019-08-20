package mpcclient;

import mpctestclient.MPCRunConfig;
import org.testng.annotations.Test;

public class MPCTestSimulatedCard10players {

    @Test
    void runMPCProtocol_10Players_simulatedCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 10;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL);
    }
}
