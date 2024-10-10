class apiResponse {
  public status: number;
  public message: string;
  public data?: any;
  public success: boolean;

  constructor(status: number, message: string, data?: any) {
    this.status = status;
    this.message = message;
    this.data = data;
    this.success = this.isSuccess();
  }

  isSuccess(): boolean {
    return this.status >= 200 && this.status < 300;
  }
}

export default apiResponse;
