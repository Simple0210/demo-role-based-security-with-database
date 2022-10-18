package uz.simplecode.rolebasedsecurityapp.service;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import uz.simplecode.rolebasedsecurityapp.mapper.GroupMapper;
import uz.simplecode.rolebasedsecurityapp.entity.Group;
import uz.simplecode.rolebasedsecurityapp.payload.ApiResponse;
import uz.simplecode.rolebasedsecurityapp.payload.req.GroupReqDto;
import uz.simplecode.rolebasedsecurityapp.payload.res.GroupResDto;
import uz.simplecode.rolebasedsecurityapp.repository.GroupRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class GroupServiceImpl implements GroupService {

    private final GroupRepository groupRepository;

    public GroupServiceImpl(GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    @Override
    public ResponseEntity<ApiResponse<List<GroupResDto>>> getAllGroups() {
        ApiResponse<List<GroupResDto>> response = new ApiResponse<>();
        List<String> errors = new ArrayList<>();
        try {
            List<GroupResDto> collect = groupRepository.findAll().stream().map(GroupMapper::parseToResDto).collect(Collectors.toList());
            response.setData(collect);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception e) {
            response.setSuccess(false);
            errors.add(e.getMessage());
            response.setErrors(errors);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<GroupResDto>> getGroupById(UUID id) {
        ApiResponse<GroupResDto> response = new ApiResponse<>();
        List<String> errors = new ArrayList<>();
        try {
            Optional<Group> byId = groupRepository.findById(id);
            if (byId.isPresent()) {
                response.setData(GroupMapper.parseToResDto(byId.get()));
                return ResponseEntity.status(HttpStatus.OK).body(response);
            } else {
                response.setSuccess(false);
                errors.add("Group topilmadi!");
                response.setErrors(errors);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }
        } catch (Exception e) {
            response.setSuccess(false);
            errors.add("Error: " + e.getMessage());
            response.setErrors(errors);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<String>> saveNewGroup(GroupReqDto groupReqDto) {
        ApiResponse<String> response = new ApiResponse<>();
        List<String> errors = new ArrayList<>();
        try {
            groupRepository.save(GroupMapper.parseToEntity(groupReqDto));
            response.setData("Group ma`lumotlari muvaffaqiyatli saqlandi!");
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception e) {
            response.setSuccess(false);
            errors.add("Error: " + e.getMessage());
            response.setErrors(errors);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<String>> editGroup(UUID id, GroupReqDto groupReqDto) {
        ApiResponse<String> response = new ApiResponse<>();
        List<String> errors = new ArrayList<>();
        try {
            Optional<Group> byId = groupRepository.findById(id);
            if (byId.isPresent()){
                Group group = GroupMapper.parseToEntity(groupReqDto);
                group.setId(byId.get().getId());
                groupRepository.save(group);
                response.setData("Group ma`lumotlari muvaffaqiyatli o`zgartirildi!");
                return ResponseEntity.status(HttpStatus.OK).body(response);
            }else {
                response.setSuccess(false);
                errors.add("Group topilmadi!");
                response.setErrors(errors);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }
        } catch (Exception e) {
            response.setSuccess(false);
            errors.add("Error: " + e.getMessage());
            response.setErrors(errors);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<String>> deleteGroup(UUID id) {
        ApiResponse<String> response = new ApiResponse<>();
        List<String> errors = new ArrayList<>();
        try {
            Optional<Group> byId = groupRepository.findById(id);
            if (byId.isPresent()){
                groupRepository.deleteById(id);
                response.setData("Group ma`lumotlari muvaffaqiyatli o`chirildi!");
                return ResponseEntity.status(HttpStatus.OK).body(response);
            }else {
                response.setSuccess(false);
                errors.add("Group topilmadi!");
                response.setErrors(errors);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }
        }catch (Exception e){
            response.setSuccess(false);
            errors.add("Error: " + e.getMessage());
            response.setErrors(errors);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}
