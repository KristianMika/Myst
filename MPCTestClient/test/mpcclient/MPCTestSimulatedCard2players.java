package mpcclient;

import mpctestclient.MPCRunConfig;
import org.testng.annotations.Test;

public class MPCTestSimulatedCard2players {

    @Test
    void runMPCProtocol_2Players_simulatedCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 2;
        runCfg.numSingleOpRepeats = 1;
        runCfg.testCardType = MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL;

        mpctestclient.MPCTestClient.MPCRunDemo(runCfg);
    }
}
