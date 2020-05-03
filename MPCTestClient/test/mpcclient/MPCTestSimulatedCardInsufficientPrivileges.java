package mpcclient;

import mpctestclient.MPCRunConfig;
import org.testng.annotations.Test;

public class MPCTestSimulatedCardInsufficientPrivileges {
    @Test
    void MPCTestSimulatedCardInsufficientPrivileges() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 1;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_InsufficientPrivileges(runCfg, MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL);
    }
}
