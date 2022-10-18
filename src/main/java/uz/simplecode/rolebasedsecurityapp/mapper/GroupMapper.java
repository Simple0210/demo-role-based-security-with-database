package uz.simplecode.rolebasedsecurityapp.mapper;

import uz.simplecode.rolebasedsecurityapp.entity.Group;
import uz.simplecode.rolebasedsecurityapp.payload.req.GroupReqDto;
import uz.simplecode.rolebasedsecurityapp.payload.res.GroupResDto;

public class GroupMapper {

    public static GroupResDto parseToResDto(Group group) {
        return GroupResDto
                .builder()
                .id(group.getId())
                .groupName(group.getGroupName())
                .build();
    }

    public static Group parseToEntity(GroupReqDto groupReqDto){
        return Group
                .builder()
                .groupName(groupReqDto.getGroupName())
                .build();
    }
}
