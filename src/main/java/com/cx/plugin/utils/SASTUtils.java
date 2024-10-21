package com.cx.plugin.utils;

import java.net.MalformedURLException;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cx.plugin.CxScanPlugin;
import com.cx.restclient.CxClientDelegator;
import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.ScannerType;
import com.cx.restclient.exception.CxClientException;
import com.cx.restclient.sast.utils.LegacyClient;

public class SASTUtils {

	public static LegacyClient getInstance(CxScanConfig config, Logger log)
			throws MalformedURLException, CxClientException {
		return new LegacyClient(config, log) {
		};
	}

	private static final Logger log = LoggerFactory.getLogger(SASTUtils.class);
	private CxClientDelegator clientDelegator;

	public static String loginToServer(URL url, String username, String pssd) {
		String version = null;
		String result = "";
		try {
			CxScanConfig scanConfig = new CxScanConfig(url.toString().trim(), username, pssd,
					CxScanPlugin.PLUGIN_ORIGIN, true);
			scanConfig.addScannerType(ScannerType.SAST);
			LegacyClient clientCommon = getInstance(scanConfig, log);
			version = clientCommon.login(true);
			return version;
		} catch (Exception ex) {
			result = ex.getMessage();
			return version;
		}
	}
}
