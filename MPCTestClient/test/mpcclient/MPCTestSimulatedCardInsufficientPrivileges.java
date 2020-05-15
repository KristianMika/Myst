package mpcclient;

import mpctestclient.MPCRunConfig;
import org.testng.annotations.Test;

public class MPCTestSimulatedCardInsufficientPrivileges {
    @Test
    void runMPCTestSimulatedCardInsufficientPrivileges() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 5;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_InsufficientPrivileges(runCfg, MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL);
    }

    @Test
    void runMPCTestSimulatedCardInsufficientPrivileges_1_sim_player() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 1;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_InsufficientPrivileges(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
    }

    @Test
    void runMPCTestSimulatedCardInsufficientPrivileges_2_sim_players() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 2;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_InsufficientPrivileges(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
    }

    @Test
    void runMPCTestSimulatedCardInsufficientPrivileges_10_sim_players() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 10;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_InsufficientPrivileges(runCfg, MPCRunConfig.CARD_TYPE.PHYSICAL);
    }
}
