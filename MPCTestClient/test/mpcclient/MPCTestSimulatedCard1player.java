package mpcclient;

import mpctestclient.MPCRunConfig;
import org.testng.annotations.Test;

public class MPCTestSimulatedCard1player {

    @Test
    void runMPCProtocol_1Player_simulatedCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 1;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170920(runCfg, MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL);
    }
}
