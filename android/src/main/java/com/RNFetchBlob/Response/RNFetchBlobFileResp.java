package com.RNFetchBlob.Response;

import android.util.Log;

import com.RNFetchBlob.RNFetchBlobConst;
import com.RNFetchBlob.RNFetchBlobProgressConfig;
import com.RNFetchBlob.RNFetchBlobReq;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.IOException;

import java.util.Arrays;

import okhttp3.MediaType;
import okhttp3.ResponseBody;
import okio.Buffer;
import okio.BufferedSource;
import okio.Okio;
import okio.Source;
import okio.Timeout;

import com.bigswing.BSCrypto;

/**
 * Created by wkh237 on 2016/7/11.
 */
public class RNFetchBlobFileResp extends ResponseBody {

    private static final String TAG = "RNFetchBlob";

    String mTaskId;
    ResponseBody originalBody;
    String mPath;
    long bytesDownloaded = 0;
    ReactApplicationContext rctContext;
    FileOutputStream ofStream;

    // Added by Rick Terrill November 2017
    BSCrypto crypto;
    OutputStream encryptor;
    boolean useEncryption;

    public RNFetchBlobFileResp(ReactApplicationContext ctx, String taskId, ResponseBody body, String path,
            boolean overwrite, boolean doEncryption) throws IOException {
        super();
        this.rctContext = ctx;
        this.mTaskId = taskId;
        this.originalBody = body;
        assert path != null;
        this.mPath = path;

        this.useEncryption = doEncryption;
        Log.i(TAG, doEncryption ? "encrypting this file" : "NOT encrypting this file");

        if (path != null) {
            boolean appendToExistingFile = !overwrite;
            path = path.replace("?append=true", "");
            mPath = path;
            File f = new File(path);

            File parent = f.getParentFile();
            if (!parent.exists() && !parent.mkdirs()) {
                throw new IllegalStateException("Couldn't create dir: " + parent);
            }

            if (f.exists() == false) {
                f.createNewFile();
            }
            ofStream = new FileOutputStream(new File(path), appendToExistingFile);

            // optionally setup encryptor
            if (doEncryption == true) {
                crypto = new BSCrypto();
                try {
                    String[] tokens = path.split("/");
                    String filename = tokens[tokens.length - 1];
                    Log.d(TAG, "filename: " + filename);
                    byte[] key = crypto.generateKey(filename);
                    encryptor = crypto.createEncryptor(ofStream, key);
                } catch (Exception ex) {
                    Log.e(TAG, "exception creating encryptor", ex);
                }
            }
        }
    }

    @Override
    public MediaType contentType() {
        return originalBody.contentType();
    }

    @Override
    public long contentLength() {
        return originalBody.contentLength();
    }

    @Override
    public BufferedSource source() {
        ProgressReportingSource countable = new ProgressReportingSource();
        return Okio.buffer(countable);
    }

    private class ProgressReportingSource implements Source {
        @Override
        public long read(Buffer sink, long byteCount) throws IOException {

            try {
                byte[] bytes = new byte[(int) byteCount];
                long read = originalBody.byteStream().read(bytes, 0, (int) byteCount);
                bytesDownloaded += read > 0 ? read : 0;
                if (read > 0) {
                    if (useEncryption == true) {
                        encryptor.write(bytes, 0, (int) read);
                    } else {
                        ofStream.write(bytes, 0, (int) read);
                    }
                }
                RNFetchBlobProgressConfig reportConfig = RNFetchBlobReq.getReportProgress(mTaskId);
                if (reportConfig != null && contentLength() != 0
                        && reportConfig.shouldReport(bytesDownloaded / contentLength())) {
                    WritableMap args = Arguments.createMap();
                    args.putString("taskId", mTaskId);
                    args.putString("written", String.valueOf(bytesDownloaded));
                    args.putString("total", String.valueOf(contentLength()));
                    rctContext.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                            .emit(RNFetchBlobConst.EVENT_PROGRESS, args);
                }
                return read;
            } catch (Exception ex) {
                return -1;
            }
        }

        @Override
        public Timeout timeout() {
            return null;
        }

        @Override
        public void close() throws IOException {
            ofStream.close();

        }
    }
}
