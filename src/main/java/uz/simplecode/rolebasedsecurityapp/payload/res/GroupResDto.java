package uz.simplecode.rolebasedsecurityapp.payload.res;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@Builder
public class GroupResDto {
    private UUID id;
    private String groupName;
}
