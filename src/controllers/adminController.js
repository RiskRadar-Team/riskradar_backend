import AdminService from "../services/adminService.js";
import ApiResponse from "../utils/ApiResponse.js";
import catchAsync from "../utils/catchAsync.js";

class AdminContoller {
  static createAdminController = catchAsync(async (request, response) => {
    const admin = await AdminService.createAdmin(request.body);
    response
      .status(201)
      .json(new ApiResponse(201, "Admin created successfully", admin));
  });
}

export default AdminContoller;
