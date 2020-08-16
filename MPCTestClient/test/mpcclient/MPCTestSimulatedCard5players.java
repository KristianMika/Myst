package mpcclient;

import mpctestclient.MPCRunConfig;
import org.testng.annotations.Test;

public class MPCTestSimulatedCard5players {

    @Test
    void runMPCProtocol_5Players_simulatedCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 5;
        runCfg.numSingleOpRepeats = 1;
        runCfg.testCardType = MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL;

        mpctestclient.MPCTestClient.MPCRunDemo(runCfg);
    }
}
