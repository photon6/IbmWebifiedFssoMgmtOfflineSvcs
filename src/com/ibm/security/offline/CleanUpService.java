package com.ibm.security.offline;

/**
 * This deletes the log files downloaded by the fetch-isam-crontab.sh script, as well as 
 * the ZIP files created by the zipRetrievedLogs.sh script - both reside in the 
 * /home/wasadmin/ICIO_FIM_Util/logging directory on this local TFIM server.
 * 
 * @author rkhanna@us.ibm.com
 * 
 * Change history
 * --------------------------------------------------------------------------------------------------
 * | Version	|	Date		| Changed by 			| Change Description						|
 * |------------------------------------------------------------------------------------------------|
 * | 1.0		|	02/27/2017	| rkhanna@us.ibm.com 	| Added inital clean up logic				|
 * |------------------------------------------------------------------------------------------------|
 * | 1.1		|	03/08/2017	| rkhanna@us.ibm.com 	| Added 'like files' logic					|
 * --------------------------------------------------------------------------------------------------
 * | 1.2		|	03/08/2017	| rkhanna@us.ibm.com 	| Removed flawed logic in 'like files'		|
 * |			|				|						| method									|
 * --------------------------------------------------------------------------------------------------
 * | 132		|	04/04/2017	| rkhanna@us.ibm.com 	| Fixed issue causing memory leaks that 	|
 * |			|				|						| resulted in core and heap dumps (IMW-1636)|
 * |			|				|						| Also fixed IMW-1436						|
 * --------------------------------------------------------------------------------------------------
 * 
 */

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.InputMismatchException;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import com.ibm.security.util.FileUtil;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;

public class CleanUpService {
	
	private static final String W3ID_LOGS_FETCH_MF_FILE_PROP = "W3ID_LOGS_FETCH_MF_FILE";
	private static final String W3ID_LOGS_FETCH_MF_FILE_PROCESSING_PROP = "W3ID_LOGS_FETCH_MF_FILE_PROCESSING";
	private static final String W3ID_LOGS_LOCAL_PATH_PROP = "W3ID_LOGS_LOCAL_PATH";
	private static final String W3ID_LOGS_NOTIFICATION_MF_FILE_PROP = "W3ID_LOGS_NOTIFICATION_MF_FILE";
	private static final String W3ID_LOGS_EXPIRATION_INTERVAL_PROP = "W3ID_LOGS_EXPIRATION_INTERVAL";
	private static final String TIMEFRAME_PATTERN_MF_PROP = "TIMEFRAME_PATTERN_MF";
	
	private static final Date now = new Date();
	
	private static final String LOGS_FETCHED_MF_SUFFIX_RETREIVED = "retrieved";
	private static final String LOGS_FETCH_MF_SUFFIX_NOTIFIED = "notified";
	
	private static int expirationInterval = 0;
	private static long expired = 0;
	private static Date expiredDT;

	private static SimpleDateFormat retrievedLogsSDF;
	
	private static HashSet<String> retrievedLogsKeys;

	public CleanUpService() throws IOException {
		Logger.debug("Inside contructor " + getClass().getName() 
				+ "()");
		
		PropertiesManager.loadApplicationProperties();
		
		expirationInterval = new Integer(PropertiesManager.getApplicationProperty(W3ID_LOGS_EXPIRATION_INTERVAL_PROP)).intValue();
		retrievedLogsSDF = new SimpleDateFormat(PropertiesManager.getApplicationProperty(TIMEFRAME_PATTERN_MF_PROP));
		
		expired = (now.getTime() - (expirationInterval*1000*60*60)); // the value of hours adjusted to milliseconds
		expiredDT = new Date(expired);

	}
	
		
	public boolean fetchInProgress() {
		return new File(PropertiesManager.getApplicationProperty(W3ID_LOGS_FETCH_MF_FILE_PROCESSING_PROP)).exists();
	}
	
	public void cleanUpExpiredZips() throws InputMismatchException, ParseException, IOException {

		// to store unique downloaded log file keys
		if (retrievedLogsKeys == null) retrievedLogsKeys = new HashSet<String>(); 
		
		
		// the manifest with zipped log files prepared for user retrieval
		File notifiedFile = new File(PropertiesManager.getApplicationProperty(W3ID_LOGS_FETCH_MF_FILE_PROP) + "." + LOGS_FETCH_MF_SUFFIX_NOTIFIED);

		// the manifest with zipped log files not yet prepared
		File toNotifyFile = new File(PropertiesManager.getApplicationProperty(W3ID_LOGS_NOTIFICATION_MF_FILE_PROP));

		// to store lines from the manifest with zipped log files prepared for user retrieval
		ArrayList<String> linesOfZipsCreated = new ArrayList<String>();

		// lines from the manifest with zipped log files prepared for user retrieval
		linesOfZipsCreated = FileUtil.loadFileLinesToArrayList(notifiedFile, linesOfZipsCreated);
		
		notifiedFile.delete();
		notifiedFile.createNewFile();
		
		// to store lines from the manifest with zipped log files not yet prepared
		ArrayList<String> linesOfZipsPending = new ArrayList<String>();

		// lines from the manifest with zipped log files not yet prepared
		linesOfZipsPending = FileUtil.loadFileLinesToArrayList(toNotifyFile, linesOfZipsPending);
		toNotifyFile.delete();
		toNotifyFile.createNewFile();
		
		StringBuilder sb = new StringBuilder(); // for the manifest with zipped log files prepared for user retrieval
		
		for (Iterator<String> keyIterator = retrievedLogsKeys.iterator(); keyIterator.hasNext();) {
			String key = keyIterator.next();
			 
			// for each of the lines concerning zipped log files prepared for user retrieval
			for (Iterator<String> notifiedOfZipIterator = linesOfZipsCreated.iterator(); notifiedOfZipIterator.hasNext();) {
				String line = notifiedOfZipIterator.next();
				if (line.contains(key)) { // if the line contains the key 
					int removeIt = fileShouldBeDeleted(line, 2, 3);
	 				if (removeIt == 1) { // if the zip file should be removed b/c it has expired
	 					Logger.debug("Log file at end of this line will be deleted, as well as this line: " + line);
					
						File fileToDelete = new File(PropertiesManager.getApplicationProperty(W3ID_LOGS_LOCAL_PATH_PROP) + "/" + key + ".zip");
						
						boolean removed = FileUtil.removeFile(fileToDelete.getAbsolutePath()); // delete the zip file
						if (removed) {
							Logger.info(fileToDelete .getAbsolutePath()+ " has been removed at " + retrievedLogsSDF.format(new Date()));
							Logger.debug(fileToDelete .getAbsolutePath()+ " has been removed at " + retrievedLogsSDF.format(new Date()));
							linesOfZipsPending.remove(key);						
						}
	 				} else if (removeIt == 2) {
						linesOfZipsPending.remove(key);						
					} else { // since the zip file should not be deleted
						sb.append(line); // store the line for file overwrite
						sb.append(System.lineSeparator());
	 					Logger.debug("This line will be preserved: " + line);
					} // end if (fileShouldBeDeleted(line, 2, 3))
				} // end if (line.contains(key))
				
			} // end for (Iterator<String> notifiedOfZipIterator = linesOfZipsCreated.iterator(); notifiedOfZipIterator.hasNext();)
		} // end for (Iterator<String> keyIterator = retrievedLogsKeys.iterator(); keyIterator.hasNext();)
		
		if (sb.length() > 0) {

			Logger.debug("Contents to new notified MF log file \"" + notifiedFile.getAbsolutePath() + "\": ");
			Logger.debug(">>" + sb.toString() + "<<");
	
			FileUtil.writeToFile(notifiedFile.getAbsolutePath(), sb.toString(), true);
			
			if (!linesOfZipsPending.isEmpty()) {
				sb.delete(0, sb.length()); // re-init for use
				Logger.debug("Lines for " + toNotifyFile.getAbsolutePath() + ": ");
				Logger.debug(linesOfZipsPending.toString());
				
				if (sb.length() > 0) {

					Logger.debug("Contents to new notification MF log file \"" + toNotifyFile.getAbsolutePath() + "\": ");
					Logger.debug(">>" + sb.toString() + "<<");
			
					FileUtil.writeToFile(toNotifyFile.getAbsolutePath(), sb.toString(), true);
				}
			}
	
			sb = null;
		}

	}
	
	
	@SuppressWarnings("resource")
	public HashSet<String > cleanUpExpiredLogs() throws Exception {		
		Logger.debug("No logs being fetched right now...");
		
		// to store unique downloaded log file keys
		if (retrievedLogsKeys == null) retrievedLogsKeys = new HashSet<String>(); 
		
		// to store lines from the retrieved logs file manifest file
		ArrayList<String> linesOfLogsRetrieved = new ArrayList<String>();   
	
		// the retrieved logs file manifest file
		File retrievedLogsFile = new File(PropertiesManager.getApplicationProperty(W3ID_LOGS_FETCH_MF_FILE_PROP) + "." + LOGS_FETCHED_MF_SUFFIX_RETREIVED);
		
		if (!retrievedLogsFile.exists()) { // if the retrieved logs file manifest file does not exist
			String msg = retrievedLogsFile.getAbsolutePath() + " does not exist. Please check configuration.";
			Logger.logToAllLevels(msg);
			throw new FileNotFoundException(msg); // throw the exception
		}
		
		// gather lines from the retrieved logs file manifest file
		linesOfLogsRetrieved = FileUtil.loadFileLinesToArrayList(retrievedLogsFile, linesOfLogsRetrieved);
			
		if (linesOfLogsRetrieved.isEmpty()) {
			
			Logger.debug(retrievedLogsFile.getAbsolutePath() + " is empty");
			
		} else {
			
			for (Iterator<String> linesOfLogsRetrievedIterator = linesOfLogsRetrieved.iterator(); linesOfLogsRetrievedIterator.hasNext();) {
				String line = linesOfLogsRetrievedIterator.next();
				String lines[] = PropertiesManager.parseProps(line, ",");
				String key = lines[0];
				retrievedLogsKeys.add(key);
			}
			
			if (retrievedLogsKeys.isEmpty()) {
				Logger.debug("No keys derived from file: " + retrievedLogsFile.getAbsolutePath());
			} else {
				
				Logger.debug("Keys: " + retrievedLogsKeys.toString());
				
				// to store lines from the retrieved logs file manifest that represent expired log files 
				ArrayList<String> linesOfLogsToDelete = new ArrayList<String>(); 

				HashSet<Boolean> success = new HashSet<Boolean>(); // not sure if we need this
				
				StringBuilder sb = new StringBuilder(); // sb to append or overwrite manifest files

				// the download logs file manifest that represent expired log files 
				File mfLogsFile = new File(PropertiesManager.getApplicationProperty(W3ID_LOGS_FETCH_MF_FILE_PROP));
				
				// cycle over each lines= from the retrieved logs file manifest 
				for (int i = 0; i < linesOfLogsRetrieved.size(); i++) {
					
					String line = linesOfLogsRetrieved.get(i);

					// get the determination of whether the log file in this line should be deleted because it has expired
					int removeIt = fileShouldBeDeleted(line, 2, 3);  
					
					if (removeIt == 0) { // if the log file in this line should NOT be removed
						sb.append(line); // prepare to write this line back into the replacement log file 
						sb.append(System.lineSeparator());
						Logger.debug("Log file at end of this line will not be removed, and neither will this line: " + line);
					} else {
						Logger.debug("Log file at end of this line will be deleted, as well as this line: " + line);
						linesOfLogsToDelete.add(line); // store the line to later delete expired log file it specified
					}

					success.add(new Boolean(removeIt==0 | removeIt == 2)?true:false); // not sure if we need this
					
				} // end for (int i = 0; i < linesOfLogsRetrieved.size(); i++)
				
				// to store unique log files (fully qualified paths) 
				HashSet<String> logsToDelete = extractLogFilesToDelete(linesOfLogsToDelete);
				
				if (logsToDelete.isEmpty()) {
					Logger.debug("There are no log files to delete");
				} else { // since there are log files to delete
					
					if (sb.length() > 0) { // if we accounted for new content for the manifest files

						retrievedLogsFile.delete();
						retrievedLogsFile.createNewFile();
						
						Logger.debug("Contents to new retrieved log file \"" + retrievedLogsFile.getAbsolutePath() + ": ");
						Logger.debug(sb.toString());
				
						// overwrite the retrieved log files manifest
						FileUtil.writeToFile(retrievedLogsFile.getAbsolutePath(), sb.toString(), true);
						
						Logger.debug("Contents to new MF log file \"" + mfLogsFile.getAbsolutePath() + ": ");
						Logger.debug(sb.toString());
				
						// overwrite the download log files manifest
						FileUtil.writeToFile(mfLogsFile.getAbsolutePath(), sb.toString(), true);
						sb = null;
					}

					sb.delete(0, sb.length()); // prepare for another manifest overwrite
					
					// to store lines of log files awaiting to be fetched from the download log file manifest
					ArrayList<String> linesOfLogsPendingFetch = new ArrayList<String>();

					// the lines of log files awaiting to be fetched from the download log file manifest
					linesOfLogsPendingFetch = FileUtil.loadFileLinesToArrayList(mfLogsFile, "TIME", false, linesOfLogsPendingFetch);
					
					for (Iterator<String> iterator = linesOfLogsPendingFetch.iterator(); iterator.hasNext();) {
						sb.append(iterator.next());
						sb.append(System.lineSeparator());			
					}
					if (sb.length() != 0) {
						Logger.debug("Contents to new MF log file \"" + retrievedLogsFile.getAbsolutePath() + ": ");
						Logger.debug(sb.toString());

						// add lines of files not yet downloaded to the download log files manifest				
						FileUtil.writeToFile(mfLogsFile.getAbsolutePath(), sb.toString(), false);
						sb = null;
					}
					
					logsToDelete = getLikeFiles(logsToDelete);

					// cycle over each log file intending to delete
					for (Iterator<String> iterator = logsToDelete.iterator(); iterator.hasNext();) {
						String fileToDelete = (String) iterator.next();
						boolean removed = FileUtil.removeFile(fileToDelete); // delete the log file
						if (removed) {
							Logger.info(fileToDelete + " has been removed at " + retrievedLogsSDF.format(new Date()));
						}
					}

				}
				
				
			} // end else for if (retrievedLogsKeys.isEmpty())
		} // end else for if (linesOfLogsRetrieved.isEmpty()) {
		
		return retrievedLogsKeys;

	}
	
	private HashSet<String> getLikeFiles(HashSet<String> logFiles) throws Exception {
		Logger.debug("Looking for like files");
		HashSet<String> likeFiles = new HashSet<String>();
		
		try {
			for (Iterator<String> iterator = logFiles.iterator(); iterator.hasNext();) {
				String logFileFullPath = iterator.next();
				Logger.debug("Log file full path: " + logFileFullPath);
				File fileFullPath = new File(logFileFullPath);
				String logFile = fileFullPath.getName();
				Logger.debug("Log file: " + logFile);
				File parentDir = new File(fileFullPath.getParent());
				Logger.debug("Log file's parent path: " + parentDir.getAbsolutePath());
				String[] dirFiles = parentDir.list();
				for (int i = 0; i < dirFiles.length; i++) {
					Logger.debug("Inspecting " + dirFiles[i]);
					if (dirFiles[i].contains(logFile)){
						Logger.debug("Found a like file: " + parentDir.getAbsolutePath() + "/" + dirFiles[i]);
						likeFiles.add(parentDir.getAbsolutePath() + "/" + dirFiles[i]);
					}
				}
			}
			
			if (!likeFiles.isEmpty()) {
				logFiles.addAll(likeFiles);
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
		
		return logFiles;
	}
	
	private HashSet<String> extractLogFilesToDelete(ArrayList<String> mfLines) {
		HashSet<String> logsToDelete = new HashSet<String>();
		for (Iterator<String> iterator = mfLines.iterator(); iterator.hasNext();) {
			String mfLine = iterator.next();
			String[] parsedLine = PropertiesManager.parseProps(mfLine, ",");
			logsToDelete.add(parsedLine[3]);
		}
		
		return logsToDelete;
	}
	
	/*
	 * 0 = should not be deleted
	 * 1 = should be deleted
	 * 2 = does not exist, or has been deleted
	 */
	private int fileShouldBeDeleted(String mfLine, int datePosition, int logFilePosition) throws ParseException, InputMismatchException, FileNotFoundException {
		String[] parsedLine = PropertiesManager.parseProps(mfLine, ",");
		int removeIt = 0;

		Date dt = retrievedLogsSDF.parse(parsedLine[datePosition]);
		File file = null;
		
		Logger.debug("The time of \"" + parsedLine[logFilePosition] + "\": " + retrievedLogsSDF.format(dt));
		Logger.debug("Time time of expiration is: " + retrievedLogsSDF.format(expiredDT));
		
		if (isExpired(now, dt)) {
			file = new File(parsedLine[logFilePosition]);
			Logger.debug(file + " is expired");
			if (file.exists()) {
				Logger.debug(file.getAbsolutePath() + " will be deleted");
				removeIt = 1;
			} else {
				Logger.debug(file.getAbsolutePath() + " has already been deleted");
				removeIt = 2;
			}
		}
		
		return removeIt;
		
	}

	
	private boolean isExpired(Date now, Date compare) {
		boolean returnVal = false;
		
		if (compare.compareTo(now) < 0 & compare.compareTo(expiredDT) < 0) {
			Logger.debug("The time this file was downloaded is before now, and has expired");
			returnVal = true;
		} else if (compare.compareTo(now) < 0 & compare.compareTo(expiredDT) > 0) {
			Logger.debug("The time this file was downloaded is before now, but has not yet expired");
		}
		
		return returnVal;
	}

	private boolean expiredInNextHour(Date now, Date compare) {
		boolean returnVal = false;
		
		if (compare.compareTo(now) < 0 & compare.compareTo(expiredDT) < 0) {
			Logger.debug("The time this file was downloaded is before now, and has expired");
			returnVal = true;
		} else if (compare.compareTo(now) < 0 & compare.compareTo(expiredDT) > 0) {
			Logger.debug("The time this file was downloaded is before now, but has not yet expired");
		}
		
		return returnVal;
	}
	
	public static void main(String[] args) throws Exception {
		
//		boolean debug = false;
//		try {
//			debug = Boolean.getBoolean(System.getProperty("debug"));
//		} catch (Exception ignore) {}
		
		CleanUpService svc = new CleanUpService();
		
		if (!svc.fetchInProgress()) {
			Logger.debug("Cleaning up expired logs");
			svc.cleanUpExpiredLogs();
			Logger.debug("Cleaning up expired zips");
			svc.cleanUpExpiredZips();
			Logger.debug("Cleaning up process completed");
		}
		

	}




	public static HashSet<String> getRetrievedLogsKeys() {
		return retrievedLogsKeys;
	}




	public static void setRetrievedLogsKeys(HashSet<String> retrievedLogsKeys) {
		CleanUpService.retrievedLogsKeys = retrievedLogsKeys;
	}
	
	

}
