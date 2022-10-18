package uz.simplecode.rolebasedsecurityapp.service;

import org.springframework.http.ResponseEntity;
import uz.simplecode.rolebasedsecurityapp.payload.ApiResponse;
import uz.simplecode.rolebasedsecurityapp.payload.req.GroupReqDto;
import uz.simplecode.rolebasedsecurityapp.payload.res.GroupResDto;

import java.util.List;
import java.util.UUID;

public interface GroupService {

    ResponseEntity<ApiResponse<List<GroupResDto>>> getAllGroups();

    ResponseEntity<ApiResponse<GroupResDto>> getGroupById(UUID id);

    ResponseEntity<ApiResponse<String>> saveNewGroup(GroupReqDto groupReqDto);

    ResponseEntity<ApiResponse<String>> editGroup(UUID id, GroupReqDto groupReqDto);

    ResponseEntity<ApiResponse<String>> deleteGroup(UUID id);


}
