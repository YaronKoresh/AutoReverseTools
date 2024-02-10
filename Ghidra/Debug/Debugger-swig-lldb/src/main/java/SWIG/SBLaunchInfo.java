/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.1
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package SWIG;

public class SBLaunchInfo {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBLaunchInfo(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBLaunchInfo obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBLaunchInfo(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBLaunchInfo(String[] argv) {
    this(lldbJNI.new_SBLaunchInfo(argv), true);
  }

  public java.math.BigInteger GetProcessID() {
    return lldbJNI.SBLaunchInfo_GetProcessID(swigCPtr, this);
  }

  public long GetUserID() {
    return lldbJNI.SBLaunchInfo_GetUserID(swigCPtr, this);
  }

  public long GetGroupID() {
    return lldbJNI.SBLaunchInfo_GetGroupID(swigCPtr, this);
  }

  public boolean UserIDIsValid() {
    return lldbJNI.SBLaunchInfo_UserIDIsValid(swigCPtr, this);
  }

  public boolean GroupIDIsValid() {
    return lldbJNI.SBLaunchInfo_GroupIDIsValid(swigCPtr, this);
  }

  public void SetUserID(long uid) {
    lldbJNI.SBLaunchInfo_SetUserID(swigCPtr, this, uid);
  }

  public void SetGroupID(long gid) {
    lldbJNI.SBLaunchInfo_SetGroupID(swigCPtr, this, gid);
  }

  public SBFileSpec GetExecutableFile() {
    return new SBFileSpec(lldbJNI.SBLaunchInfo_GetExecutableFile(swigCPtr, this), true);
  }

  public void SetExecutableFile(SBFileSpec exe_file, boolean add_as_first_arg) {
    lldbJNI.SBLaunchInfo_SetExecutableFile(swigCPtr, this, SBFileSpec.getCPtr(exe_file), exe_file, add_as_first_arg);
  }

  public SBListener GetListener() {
    return new SBListener(lldbJNI.SBLaunchInfo_GetListener(swigCPtr, this), true);
  }

  public void SetListener(SBListener listener) {
    lldbJNI.SBLaunchInfo_SetListener(swigCPtr, this, SBListener.getCPtr(listener), listener);
  }

  public long GetNumArguments() {
    return lldbJNI.SBLaunchInfo_GetNumArguments(swigCPtr, this);
  }

  public String GetArgumentAtIndex(long idx) {
    return lldbJNI.SBLaunchInfo_GetArgumentAtIndex(swigCPtr, this, idx);
  }

  public void SetArguments(String[] argv, boolean append) {
    lldbJNI.SBLaunchInfo_SetArguments(swigCPtr, this, argv, append);
  }

  public long GetNumEnvironmentEntries() {
    return lldbJNI.SBLaunchInfo_GetNumEnvironmentEntries(swigCPtr, this);
  }

  public String GetEnvironmentEntryAtIndex(long idx) {
    return lldbJNI.SBLaunchInfo_GetEnvironmentEntryAtIndex(swigCPtr, this, idx);
  }

  public void SetEnvironmentEntries(String[] envp, boolean append) {
    lldbJNI.SBLaunchInfo_SetEnvironmentEntries(swigCPtr, this, envp, append);
  }

  public void SetEnvironment(SBEnvironment env, boolean append) {
    lldbJNI.SBLaunchInfo_SetEnvironment(swigCPtr, this, SBEnvironment.getCPtr(env), env, append);
  }

  public SBEnvironment GetEnvironment() {
    return new SBEnvironment(lldbJNI.SBLaunchInfo_GetEnvironment(swigCPtr, this), true);
  }

  public void Clear() {
    lldbJNI.SBLaunchInfo_Clear(swigCPtr, this);
  }

  public String GetWorkingDirectory() {
    return lldbJNI.SBLaunchInfo_GetWorkingDirectory(swigCPtr, this);
  }

  public void SetWorkingDirectory(String working_dir) {
    lldbJNI.SBLaunchInfo_SetWorkingDirectory(swigCPtr, this, working_dir);
  }

  public long GetLaunchFlags() {
    return lldbJNI.SBLaunchInfo_GetLaunchFlags(swigCPtr, this);
  }

  public void SetLaunchFlags(long flags) {
    lldbJNI.SBLaunchInfo_SetLaunchFlags(swigCPtr, this, flags);
  }

  public String GetProcessPluginName() {
    return lldbJNI.SBLaunchInfo_GetProcessPluginName(swigCPtr, this);
  }

  public void SetProcessPluginName(String plugin_name) {
    lldbJNI.SBLaunchInfo_SetProcessPluginName(swigCPtr, this, plugin_name);
  }

  public String GetShell() {
    return lldbJNI.SBLaunchInfo_GetShell(swigCPtr, this);
  }

  public void SetShell(String path) {
    lldbJNI.SBLaunchInfo_SetShell(swigCPtr, this, path);
  }

  public boolean GetShellExpandArguments() {
    return lldbJNI.SBLaunchInfo_GetShellExpandArguments(swigCPtr, this);
  }

  public void SetShellExpandArguments(boolean expand) {
    lldbJNI.SBLaunchInfo_SetShellExpandArguments(swigCPtr, this, expand);
  }

  public long GetResumeCount() {
    return lldbJNI.SBLaunchInfo_GetResumeCount(swigCPtr, this);
  }

  public void SetResumeCount(long c) {
    lldbJNI.SBLaunchInfo_SetResumeCount(swigCPtr, this, c);
  }

  public boolean AddCloseFileAction(int fd) {
    return lldbJNI.SBLaunchInfo_AddCloseFileAction(swigCPtr, this, fd);
  }

  public boolean AddDuplicateFileAction(int fd, int dup_fd) {
    return lldbJNI.SBLaunchInfo_AddDuplicateFileAction(swigCPtr, this, fd, dup_fd);
  }

  public boolean AddOpenFileAction(int fd, String path, boolean read, boolean write) {
    return lldbJNI.SBLaunchInfo_AddOpenFileAction(swigCPtr, this, fd, path, read, write);
  }

  public boolean AddSuppressFileAction(int fd, boolean read, boolean write) {
    return lldbJNI.SBLaunchInfo_AddSuppressFileAction(swigCPtr, this, fd, read, write);
  }

  public void SetLaunchEventData(String data) {
    lldbJNI.SBLaunchInfo_SetLaunchEventData(swigCPtr, this, data);
  }

  public String GetLaunchEventData() {
    return lldbJNI.SBLaunchInfo_GetLaunchEventData(swigCPtr, this);
  }

  public boolean GetDetachOnError() {
    return lldbJNI.SBLaunchInfo_GetDetachOnError(swigCPtr, this);
  }

  public void SetDetachOnError(boolean enable) {
    lldbJNI.SBLaunchInfo_SetDetachOnError(swigCPtr, this, enable);
  }

  public String GetScriptedProcessClassName() {
    return lldbJNI.SBLaunchInfo_GetScriptedProcessClassName(swigCPtr, this);
  }

  public void SetScriptedProcessClassName(String class_name) {
    lldbJNI.SBLaunchInfo_SetScriptedProcessClassName(swigCPtr, this, class_name);
  }

  public SBStructuredData GetScriptedProcessDictionary() {
    return new SBStructuredData(lldbJNI.SBLaunchInfo_GetScriptedProcessDictionary(swigCPtr, this), true);
  }

  public void SetScriptedProcessDictionary(SBStructuredData dict) {
    lldbJNI.SBLaunchInfo_SetScriptedProcessDictionary(swigCPtr, this, SBStructuredData.getCPtr(dict), dict);
  }

}
