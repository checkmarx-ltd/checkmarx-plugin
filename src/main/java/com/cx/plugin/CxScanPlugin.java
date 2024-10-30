package com.cx.plugin;

import com.cx.restclient.CxClientDelegator;
import com.cx.restclient.sast.utils.LegacyClient;
import com.cx.plugin.configuration.CommonClientFactory;
import com.cx.plugin.dto.MavenScanResults;

import com.cx.restclient.configuration.CxScanConfig;
import com.cx.restclient.dto.Results;
import com.cx.restclient.dto.ScanResults;
import com.cx.restclient.dto.ScannerType;
import com.cx.restclient.dto.scansummary.ScanSummary;
import com.cx.restclient.exception.CxClientException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.codehaus.plexus.archiver.Archiver;
import org.codehaus.plexus.archiver.zip.ZipArchiver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.impl.MavenLoggerAdapter;
import org.sonatype.plexus.components.sec.dispatcher.DefaultSecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static com.cx.plugin.utils.CxPluginUtils.*;


/**
 * The 'scan' goal creates a single comprehensive scan, including all the modules in the reactor.
 */
@Mojo(name = "scan", aggregator = true, requiresDependencyResolution = ResolutionScope.TEST, inheritByDefault = false)
public class CxScanPlugin extends AbstractMojo {

    private static Logger log = LoggerFactory.getLogger(CxScanPlugin.class);
    public static final String PLUGIN_ORIGIN = "Maven";
    public static final String SOURCES_ZIP_NAME = "sources";
    public final static String HTML_REPORT = "htmlReport";

    /**
     * The username of the user running the scan.
     */
    @Parameter(required = false, property = "cx.username")
    private String username;

    /**
     * The password of the user running the scan.
     */
    @Parameter(required = false, property = "cx.password")
    private String password;

    /**
     * Host name of the Checkmarx application.
     */
    @Parameter(defaultValue = "http://localhost", property = "cx.url")
    private URL url;

    /**
     * The name of the project being scanned.
     */
    @Parameter(defaultValue = "${project.name}", property = "cx.projectName")
    private String projectName;

    /**
     * The full path describing the team the scan belongs to.
     */
    @Parameter(property = "cx.fullTeamPath", defaultValue = "\\CxServer")
    private String fullTeamPath;

    /**
     * Configure this field to scan the project with one of the predefined scan presets, or one of your custom presets.
     */
    @Parameter(defaultValue = "Checkmarx Default", property = "cx.preset")
    private String preset;

    /**
     * If true, an incremental scan will be performed, meaning - only modified files will be scanned.
     */
    @Parameter(defaultValue = "true", property = "cx.isIncrementalScan")
    private boolean isIncrementalScan;


    @Parameter(property = "cx.comment")
    private String comment;
    /**
     * List of folders and\or folder patterns which the scan will ignore
     */
    @Parameter(property = "cx.folderExclusions")
    private String[] folderExclusions = new String[0];

    /**
     * List of files and\or file patterns which the scan will ignore.
     */
    @Parameter(property = "cx.fileExclusions")
    private String[] fileExclusions = new String[0];

    /**
     * If true, the build will wait for the scan to end and display the results.
     * If false, the build will trigger the scan without waiting for the scan to end and the results will not be displayed
     */
    @Parameter(defaultValue = "true", property = "cx.isSynchronous")
    private boolean isSynchronous;

    /**
     * If true, a PDF report will be generated in the output directory.
     */
    @Parameter(defaultValue = "true", property = "cx.generatePDFReport")
    private boolean generatePDFReport;

    /**
     * Configure a threshold for the Critical Severity Vulnerabilities.
     * The build will fail if the sum of Critical Severity Vulnerabilities is larger than the threshold.
     * Leave empty to ignore threshold.
     */
    @Parameter(defaultValue = "-1", property = "cx.criticalSeveritiesThreshold")
    private int criticalSeveritiesThreshold;

    /**
     * Configure a threshold for the High Severity Vulnerabilities.
     * The build will fail if the sum of High Severity Vulnerabilities is larger than the threshold.
     * Leave empty to ignore threshold.
     */
    @Parameter(defaultValue = "-1", property = "cx.highSeveritiesThreshold")
    private int highSeveritiesThreshold;

    /**
     * Configure a threshold for the Medium Severity Vulnerabilities.
     * The build will fail if the sum of Medium Severity Vulnerabilities is larger than the threshold.
     * Leave empty to ignore threshold.
     */
    @Parameter(defaultValue = "-1", property = "cx.mediumSeveritiesThreshold")
    private int mediumSeveritiesThreshold;

    /**
     * Configure a threshold for the Low Severity Vulnerabilities.
     * The build will fail if the sum of Low Severity Vulnerabilities is larger than the threshold.
     * Leave empty to ignore threshold.
     */
    @Parameter(defaultValue = "-1", property = "cx.lowSeveritiesThreshold")
    private int lowSeveritiesThreshold;

    /**
     * Define a timeout (in minutes) for the scan. If the specified time has passed, the build fails.
     * Set to 0 to run the scan with no time limit.
     */
    @Parameter(defaultValue = "0", property = "cx.scanTimeoutInMinutes")
    private int scanTimeoutInMinutes;

    /**
     * If true, CxOSA will be enabled
     */
    @Parameter(defaultValue = "false", property = "cx.osaEnabled")
    private boolean osaEnabled;

    /**
     * List of Maven dependencies that will not be included in CxOSA.
     * An exclusion should be of the form: groupId.artifactId
     */
    @Deprecated
    @Parameter(property = "cx.osaExclusions")
    private String[] osaExclusions = new String[0];

    /**
     * List of Maven scopes to be ignored in CxOSA scan
     * test and provided scopes are ignored by default unless configured otherwise
     */
    @Parameter(property = "cx.osaIgnoreScopes")
    private String[] osaIgnoreScopes = new String[0];

    /**
     * Configure a threshold for the CxOSA High Severity Vulnerabilities.
     * The build will fail if the sum of High Severity Vulnerabilities is larger than the threshold.
     * Leave empty to ignore threshold.
     */
    @Parameter(defaultValue = "-1", property = "cx.osaHighSeveritiesThreshold")
    private int osaHighSeveritiesThreshold;

    /**
     * Configure a threshold for the CxOSA Medium Severity Vulnerabilities.
     * The build will fail if the sum of Medium Severity Vulnerabilities is larger than the threshold.
     * Leave empty to ignore threshold.
     */
    @Parameter(defaultValue = "-1", property = "cx.osaMediumSeveritiesThreshold")
    private int osaMediumSeveritiesThreshold;

    /**
     * Configure a threshold for the CxOSA Low Severity Vulnerabilities.
     * The build will fail if the sum of Low Severity Vulnerabilities is larger than the threshold.
     * Leave empty to ignore threshold.
     */
    @Parameter(defaultValue = "-1", property = "cx.osaLowSeveritiesThreshold")
    private int osaLowSeveritiesThreshold;

    /**
     * If true, a CxOSA PDF report will be generated in the output directory.
     */
    @Deprecated
    @Parameter(defaultValue = "true", property = "cx.osaGeneratePDFReport")
    private boolean osaGeneratePDFReport;

    /**
     * \\
     * If true, a CxOSA HTML report will be generated in the output directory.
     */
    @Deprecated
    @Parameter(defaultValue = "true", property = "cx.osaGenerateHTMLReport")
    private boolean osaGenerateHTMLReport;

    /**
     * If true, a CxOSA Json reports will be generated in the output directory.
     */
    @Parameter(defaultValue = "true", property = "cx.osaGenerateJsonReport")
    private boolean osaGenerateJsonReport;

    @Parameter(defaultValue = "false", property = "cx.enablePolicyViolations")
    private boolean enablePolicyViolations;

    /**
     * Define an output directory for the scan reports.
     */
    @Parameter(defaultValue = "${project.build.directory}/checkmarx", property = "cx.outputDirectory")
    private File outputDirectory;

    /**
     * Disables certificate verification.
     */
    @Parameter(defaultValue = "false", property = "cx.disableCertificateVerification")
    private boolean disableCertificateVerification;

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(defaultValue = "${reactorProjects}", readonly = true)
    private List<MavenProject> reactorProjects;

    @Parameter(defaultValue = "${settings}", readonly = true, required = true)
    private Settings settings;

    @Parameter(property = "serverId")
    private String serverId;

    @Component(role = org.sonatype.plexus.components.sec.dispatcher.SecDispatcher.class, hint = "default")
    private DefaultSecDispatcher securityDispatcher;

    @Component(role = Archiver.class, hint = "zip")
    private ZipArchiver zipArchiver;

    private String pluginVersion;

    public void execute() throws MojoExecutionException, MojoFailureException 
    {
        MavenLoggerAdapter.setLogger(getLog());
        printLogo(log);
        
        LegacyClient commonClient = null;
        try 
        {

            PluginDescriptor pd = (PluginDescriptor) getPluginContext().get("pluginDescriptor");
            if (pd != null) 
            {
                pluginVersion = pd.getVersion();
            }
            //resolve configuration
            CxScanConfig config = resolveConfigurationMap();
            config.setPluginVersion(pluginVersion);
            CxClientDelegator delegator = CommonClientFactory.getClientDelegatorInstance(config, log);

            //print configuration
            printConfiguration(config, osaIgnoreScopes, pluginVersion, log);

            if (!config.isSastEnabled() && !config.isOsaEnabled()) 
            {
                throw new MojoFailureException("Both SAST and OSA are disabled. exiting");
            }
            //create scans and retrieve results
            MavenScanResults ret = new MavenScanResults();

            List<ScanResults> results = new ArrayList<>();
            //initialize cx client
            try 
            {
            	commonClient = CommonClientFactory.getInstance(config, log);
            	ScanResults initResults = delegator.init();
                results.add(initResults);
            } 
            catch (Exception ex) 
            {
                if (ex.getMessage().contains("Server is unavailable")) 
                {
                    try 
                    {
                    	delegator.getSastClient().login();
                    } 
                    catch (CxClientException e) 
                    {
                        throw new MojoFailureException(e.getMessage());
                    }
                    String errorMsg = "Connection Failed.\n" +
                            "Validate the provided login credentials and server URL are correct.\n" +
                            "In addition, make sure the installed plugin version is compatible with the CxSAST version according to CxSAST release notes.";
                    throw new MojoFailureException(ex.getMessage() + ": " + errorMsg);
                }
                throw new MojoFailureException(ex.getMessage(), ex);
            }
            
            if (config.isOsaEnabled()) 
            {

                File dummyFileForOSA = null;
                try 
                {
                    dummyFileForOSA = createDummyFileForOSA();
                    Properties scannerProperties = generateOSAScanConfiguration(project.getBasedir().getAbsolutePath(), osaIgnoreScopes, dummyFileForOSA.getName());
                    config.setOsaFsaConfig(scannerProperties);
                } 
                catch (com.cx.restclient.exception.CxClientException | IOException e) 
                {
                    ret.setException((CxClientException) e);
                    log.warn(e.getMessage());
                } 
                finally 
                {
                    FileUtils.deleteQuietly(dummyFileForOSA);
                }
            }

            if(config.isSastEnabled())
            {
            	log.info("Zipping sources");
                File zipFile = zipSources(reactorProjects, zipArchiver, outputDirectory, log);
                config.setZipFile(zipFile);
            }
            
            ScanResults createScanResults = delegator.initiateScan();
            results.add(createScanResults);
            ScanResults scanResults = config.getSynchronous() ? delegator.waitForScanResults() : delegator.getLatestScanResults();

            ret.put(ScannerType.SAST, scanResults.getSastResults());
            
            if(config.isOsaEnabled())
            {
            	ret.put(ScannerType.OSA, scanResults.getOsaResults());
            }
            results.add(scanResults);
            
            if (config.getEnablePolicyViolations()) 
            {
                delegator.printIsProjectViolated(scanResults);
            }   
            
            //assert if expected exception is thrown  OR when vulnerabilities under threshold OR when policy violated
            ScanSummary scanSummary = new ScanSummary(config, ret.getSastResults(), ret.getOsaResults(), ret.getScaResults());
            if (scanSummary.hasErrors() || ret.getGeneralException() != null ||
                    (config.isSastEnabled() && (ret.getSastResults() == null || ret.getSastResults().getException() != null)) ||
                    (config.isOsaEnabled() && (ret.getOsaResults() == null || ret.getOsaResults().getException() != null)) ) 
            {
            	            	
            	StringBuilder scanFailedAtServer = new StringBuilder();
            	if( config.isSastEnabled() && (ret.getSastResults() == null || !ret.getSastResults().isSastResultsReady()) ){
            		scanFailedAtServer.append("CxSAST scan results are not found. Scan might have failed at the server or aborted by the server.\n");
            	}
            	if ( config.isOsaEnabled() && (ret.getOsaResults() == null || !ret.getOsaResults().isOsaResultsReady()) ){
                	scanFailedAtServer.append("CxSAST OSA scan results are not found. Scan might have failed at the server or aborted by the server.\n");
            	}
            	
            	if(scanSummary.hasErrors() && scanFailedAtServer.toString().isEmpty()){
            		scanFailedAtServer.append(scanSummary.toString());
            	}
            	else if (scanSummary.hasErrors()){
            		scanFailedAtServer.append("\n").append(scanSummary.toString());
            	}            	
            	printBuildFailure(scanFailedAtServer.toString(), ret, log);      
            }
            
            //Asynchronous mode
            if(!config.getSynchronous())
            {
            	ScanResults finalScanResults = getFinalScanResults(results);
                String scanHTMLSummary = delegator.generateHTMLSummary(finalScanResults);
                ret.getSummary().put(HTML_REPORT, scanHTMLSummary);
                
                if (ret.getException() != null || ret.getGeneralException() != null) 
                {
                    printBuildFailure(null, ret, log);
                }
            }
            
            if (config.getSynchronous() && config.isSastEnabled() && 
            		( (createScanResults.getSastResults() != null && createScanResults.getSastResults().getException() != null && createScanResults.getSastResults().getScanId() > 0) || 
            		( scanResults.getSastResults() != null && scanResults.getSastResults().getException() != null ) ) ) 
            {
                cancelScan(delegator);
            }
            

        } 
        catch (Exception e) 
        {
            log.error("Interrupted exception: " + e.getMessage(), e);
            throw new MojoExecutionException(e.getMessage());
        } 
    }
    
    private ScanResults getFinalScanResults(List<ScanResults> results) {
        ScanResults scanResults = new ScanResults();

        for (int i = 0; i < results.size(); i++) {
            Map<ScannerType, Results> resultsMap = results.get(i).getResults();
            for (Map.Entry<ScannerType, Results> entry : resultsMap.entrySet()) {
                if (entry != null && entry.getValue() != null && entry.getValue().getException() != null && scanResults.get(entry.getKey()) == null) {
                    scanResults.put(entry.getKey(), entry.getValue());
                }
                if (i == results.size() - 1 && entry != null && entry.getValue() != null && entry.getValue().getException() == null) {
                    scanResults.put(entry.getKey(), entry.getValue());
                }
            }
        }
        return scanResults;
    }
    
    private void cancelScan(CxClientDelegator delegator) 
    {
        try 
        {
            delegator.getSastClient().cancelSASTScan();
        } 
        catch (Exception ignored) {}
    }
    
    private File createDummyFileForOSA() throws IOException 
    {
        String dummyFilename = "dummy" + RandomStringUtils.randomNumeric(4) + ".java";
        File file = new File(project.getBasedir().getAbsolutePath(), dummyFilename);
        file.createNewFile();
        return file;
    }

    private CxScanConfig resolveConfigurationMap() throws MojoExecutionException { 
    	String folderExclusionsString = "";
        CxScanConfig scanConfig = new CxScanConfig();
        scanConfig.setCxOrigin(PLUGIN_ORIGIN);
        scanConfig.setSastEnabled(true);
        scanConfig.setDisableCertificateValidation(disableCertificateVerification);
        loadUserInfoFromSettings();
        scanConfig.setUsername(username);
        scanConfig.setPassword(password);
        scanConfig.setUrl(url.toString());// todo check
        scanConfig.setReportsDir(outputDirectory);
        scanConfig.setProjectName(projectName);
        scanConfig.setTeamPath(fullTeamPath);
        scanConfig.setPresetName(preset);
        scanConfig.setSastScanTimeoutInMinutes(scanTimeoutInMinutes);
        scanConfig.setScanComment(comment);
        scanConfig.setIncremental(isIncrementalScan);
        scanConfig.setSynchronous(isSynchronous);
        boolean thresholdEnabled = (criticalSeveritiesThreshold >= 0 || highSeveritiesThreshold >= 0 || mediumSeveritiesThreshold >= 0 || lowSeveritiesThreshold >= 0);//todo check null
        scanConfig.setSastThresholdsEnabled(thresholdEnabled);
        if (criticalSeveritiesThreshold != -1) {
            scanConfig.setSastCriticalThreshold(criticalSeveritiesThreshold);
        }

        if (highSeveritiesThreshold != -1) {
            scanConfig.setSastHighThreshold(highSeveritiesThreshold);
        }

        if (mediumSeveritiesThreshold != -1) {
            scanConfig.setSastMediumThreshold(mediumSeveritiesThreshold);
        }

        if (lowSeveritiesThreshold != -1) {
            scanConfig.setSastLowThreshold(lowSeveritiesThreshold);
        }

        scanConfig.setGeneratePDFReport(generatePDFReport);
            
        for (String folder : folderExclusions){
        	folderExclusionsString = folderExclusionsString + folder + ","; 
        }
        if(!folderExclusionsString.equals(""))
        {
        	folderExclusionsString = folderExclusionsString.substring(0, folderExclusionsString.length() - 1);   
        }
        scanConfig.setSastFolderExclusions(folderExclusionsString);
        
        if(osaEnabled){
        	scanConfig.addScannerType(ScannerType.OSA);
        }
        boolean osaThresholdEnabled = (osaHighSeveritiesThreshold >= 0 || osaMediumSeveritiesThreshold >= 0 || osaLowSeveritiesThreshold >= 0);//todo check null
        scanConfig.setOsaGenerateJsonReport(osaGenerateJsonReport);
        scanConfig.setOsaThresholdsEnabled(osaThresholdEnabled);
        scanConfig.setOsaHighThreshold(osaHighSeveritiesThreshold);
        scanConfig.setOsaMediumThreshold(osaMediumSeveritiesThreshold);
        scanConfig.setOsaLowThreshold(osaLowSeveritiesThreshold);
        scanConfig.setEnablePolicyViolations(enablePolicyViolations);

        return scanConfig;
    }

    private void loadUserInfoFromSettings() throws MojoExecutionException {
        if (this.serverId == null) {
            return;
        }

        if ((username == null || password == null) && (settings != null)) {
            Server server = this.settings.getServer(this.serverId);
            if (server != null) {
                if (username == null) {
                    username = server.getUsername();
                }
                if (password == null && server.getPassword() != null) {
                    try {
                        password = securityDispatcher.decrypt(server.getPassword());
                    } catch (SecDispatcherException ex) {
                        try {
                            securityDispatcher.setConfigurationFile(System.getProperty("user.home") + "\\.m2\\settings-security.xml");
                            password = securityDispatcher.decrypt(server.getPassword());
                        } catch (Exception e) {
                            throw new MojoExecutionException(e.getMessage());
                        }
                    }
                }
            }
        }

        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }
    }

}
